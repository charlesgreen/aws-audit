package collect

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/charlesgreen/aws-audit/internal/awsapi"
	"github.com/charlesgreen/aws-audit/internal/redact"
	"github.com/charlesgreen/aws-audit/internal/regions"
	"github.com/charlesgreen/aws-audit/internal/summarize"
)

const Version = "aws-audit/2.0"

// Options configure a collection run.
type Options struct {
	Profile      string
	OutDir       string
	RequestedCSV string
	Parallel     int
	Client       awsapi.Client
	Now          time.Time
}

// Run authenticates, dumps configuration JSON, and writes summary.md.
func Run(ctx context.Context, opts Options) error {
	if opts.Parallel <= 0 {
		opts.Parallel = 4
	}
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Client == nil {
		return fmt.Errorf("AWS client is required")
	}

	var requested []string
	if strings.TrimSpace(opts.RequestedCSV) != "" {
		var err error
		requested, err = regions.ParseRequested(opts.RequestedCSV)
		if err != nil {
			return fmt.Errorf("%w\n\n%s", err, regions.FormatCatalog(""))
		}
	}

	id, err := opts.Client.CallerIdentity(ctx)
	if err != nil {
		return fmt.Errorf("Failed to authenticate with profile %q: %w", opts.Profile, err)
	}
	part := regions.PartitionFromARN(id.ARN)
	home := regions.HomeRegion(part)

	enabled, disabled, source := discoverRegions(ctx, opts.Client, home, part)

	var scanned []string
	if requested != nil {
		scanned, err = regions.FilterForAccount(requested, part, enabled, source == "fallback")
		if err != nil {
			return err
		}
	} else {
		scanned = enabled
	}
	if len(scanned) == 0 {
		return fmt.Errorf("no regions resolved")
	}

	out := opts.OutDir
	if out == "" {
		out = fmt.Sprintf("./aws-audit-%s-%s", id.Account, opts.Now.Format("20060102-150405"))
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(out, 0o700)
	opts.OutDir = out

	c := &collector{
		opts:     opts,
		account:  id.Account,
		arn:      id.ARN,
		part:     part,
		home:     home,
		disabled: disabled,
		errLog:   filepath.Join(out, "errors.log"),
	}
	if err := os.WriteFile(c.errLog, nil, 0o600); err != nil {
		return err
	}

	meta := map[string]any{
		"account_id":          id.Account,
		"principal_arn":       id.ARN,
		"profile":             opts.Profile,
		"started_at_utc":      opts.Now.Format("20060102-150405"),
		"tool_version":        Version,
		"partition":           part,
		"home_region":         home,
		"regions_scanned":     scanned,
		"regions_not_enabled": disabled,
		"regions_requested":   requested,
	}
	if requested == nil {
		meta["regions_requested"] = []string{}
	}
	if err := c.writeJSON(filepath.Join(out, "meta.json"), meta); err != nil {
		return err
	}

	c.auditGlobal(ctx)
	c.auditRegions(ctx, scanned)

	md, err := summarize.Report(out)
	if err != nil {
		md = fmt.Sprintf("# AWS Audit Summary\n\nAccount: %s\nSummarizer error: %v\n", id.Account, err)
	}
	return os.WriteFile(filepath.Join(out, "summary.md"), []byte(md), 0o600)
}

func discoverRegions(ctx context.Context, cl awsapi.Client, home, part string) (enabled, disabled []string, source string) {
	st, err := cl.ListAccountRegions(ctx, home)
	if err == nil {
		for _, r := range st {
			switch r.Status {
			case "ENABLED", "ENABLED_BY_DEFAULT":
				enabled = append(enabled, r.Name)
			case "DISABLED", "DISABLING":
				disabled = append(disabled, r.Name)
			}
		}
		if len(enabled) > 0 {
			return enabled, disabled, "account"
		}
	}
	ec2, err := cl.EC2DescribeEnabledRegions(ctx, home)
	if err == nil && len(ec2) > 0 {
		en := map[string]bool{}
		for _, n := range ec2 {
			en[n] = true
		}
		for _, code := range regions.CodesForPartition(part) {
			if !en[code] {
				disabled = append(disabled, code)
			}
		}
		return ec2, disabled, "ec2"
	}
	return regions.DefaultCodes(part), nil, "fallback"
}

type collector struct {
	opts     Options
	account  string
	arn      string
	part     string
	home     string
	disabled []string
	errMu    sync.Mutex
	errLog   string
}

func (c *collector) dump(ctx context.Context, path string, req awsapi.Dump) json.RawMessage {
	raw, err := c.opts.Client.Dump(ctx, req)
	if err != nil {
		c.logErr(req, err)
		raw = json.RawMessage(`{}`)
	}
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	red, rerr := redact.JSON(raw)
	if rerr == nil {
		raw = red
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	_ = os.WriteFile(path, raw, 0o600)
	return raw
}

func (c *collector) writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	return os.WriteFile(path, b, 0o600)
}

func (c *collector) logErr(req awsapi.Dump, err error) {
	c.errMu.Lock()
	defer c.errMu.Unlock()
	f, e := os.OpenFile(c.errLog, os.O_APPEND|os.O_WRONLY, 0o600)
	if e != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "[%s] FAIL region=%s :: %s %s %v\n",
		time.Now().UTC().Format(time.RFC3339), req.Region, req.Service, req.Operation, err)
}

func (c *collector) auditGlobal(ctx context.Context) {
	g := filepath.Join(c.opts.OutDir, "global")
	iam := filepath.Join(g, "iam")
	c.dump(ctx, filepath.Join(iam, "account-summary.json"), awsapi.Dump{Service: "iam", Operation: "GetAccountSummary"})
	c.dump(ctx, filepath.Join(iam, "account-password-policy.json"), awsapi.Dump{Service: "iam", Operation: "GetAccountPasswordPolicy"})
	c.dump(ctx, filepath.Join(iam, "account-authorization.json"), awsapi.Dump{Service: "iam", Operation: "GetAccountAuthorizationDetails"})
	users := c.dump(ctx, filepath.Join(iam, "users.json"), awsapi.Dump{Service: "iam", Operation: "ListUsers"})
	roles := c.dump(ctx, filepath.Join(iam, "roles.json"), awsapi.Dump{Service: "iam", Operation: "ListRoles"})
	c.dump(ctx, filepath.Join(iam, "groups.json"), awsapi.Dump{Service: "iam", Operation: "ListGroups"})
	c.dump(ctx, filepath.Join(iam, "policies-local.json"), awsapi.Dump{Service: "iam", Operation: "ListPolicies", Input: map[string]string{"Scope": "Local"}})
	c.dump(ctx, filepath.Join(iam, "instance-profiles.json"), awsapi.Dump{Service: "iam", Operation: "ListInstanceProfiles"})
	c.dump(ctx, filepath.Join(iam, "saml-providers.json"), awsapi.Dump{Service: "iam", Operation: "ListSAMLProviders"})
	c.dump(ctx, filepath.Join(iam, "oidc-providers.json"), awsapi.Dump{Service: "iam", Operation: "ListOpenIDConnectProviders"})
	c.dump(ctx, filepath.Join(iam, "server-certificates.json"), awsapi.Dump{Service: "iam", Operation: "ListServerCertificates"})
	c.dump(ctx, filepath.Join(iam, "virtual-mfa-devices.json"), awsapi.Dump{Service: "iam", Operation: "ListVirtualMFADevices"})
	c.dump(ctx, filepath.Join(iam, "credential-report-generate.json"), awsapi.Dump{Service: "iam", Operation: "GenerateCredentialReport"})
	rep := c.dump(ctx, filepath.Join(iam, "credential-report.json"), awsapi.Dump{Service: "iam", Operation: "GetCredentialReport"})
	writeCredentialCSV(filepath.Join(iam, "credential-report.csv"), rep)

	for _, u := range fieldList(users, "Users", "UserName") {
		ud := filepath.Join(iam, "users", sanitize(u))
		c.dump(ctx, filepath.Join(ud, "mfa-devices.json"), awsapi.Dump{Service: "iam", Operation: "ListMFADevices", Input: map[string]string{"UserName": u}})
		keys := c.dump(ctx, filepath.Join(ud, "access-keys.json"), awsapi.Dump{Service: "iam", Operation: "ListAccessKeys", Input: map[string]string{"UserName": u}})
		c.dump(ctx, filepath.Join(ud, "attached-policies.json"), awsapi.Dump{Service: "iam", Operation: "ListAttachedUserPolicies", Input: map[string]string{"UserName": u}})
		c.dump(ctx, filepath.Join(ud, "inline-policies.json"), awsapi.Dump{Service: "iam", Operation: "ListUserPolicies", Input: map[string]string{"UserName": u}})
		c.dump(ctx, filepath.Join(ud, "groups.json"), awsapi.Dump{Service: "iam", Operation: "ListGroupsForUser", Input: map[string]string{"UserName": u}})
		for _, k := range fieldList(keys, "AccessKeyMetadata", "AccessKeyId") {
			c.dump(ctx, filepath.Join(ud, "access-key-"+sanitize(k)+"-last-used.json"), awsapi.Dump{Service: "iam", Operation: "GetAccessKeyLastUsed", Input: map[string]string{"AccessKeyId": k}})
		}
	}
	for _, r := range fieldList(roles, "Roles", "RoleName") {
		rd := filepath.Join(iam, "roles", sanitize(r))
		c.dump(ctx, filepath.Join(rd, "role.json"), awsapi.Dump{Service: "iam", Operation: "GetRole", Input: map[string]string{"RoleName": r}})
		c.dump(ctx, filepath.Join(rd, "attached-policies.json"), awsapi.Dump{Service: "iam", Operation: "ListAttachedRolePolicies", Input: map[string]string{"RoleName": r}})
		c.dump(ctx, filepath.Join(rd, "inline-policies.json"), awsapi.Dump{Service: "iam", Operation: "ListRolePolicies", Input: map[string]string{"RoleName": r}})
	}

	org := filepath.Join(g, "organizations")
	c.dump(ctx, filepath.Join(org, "describe-organization.json"), awsapi.Dump{Service: "organizations", Operation: "DescribeOrganization"})
	c.dump(ctx, filepath.Join(org, "list-accounts.json"), awsapi.Dump{Service: "organizations", Operation: "ListAccounts"})
	c.dump(ctx, filepath.Join(org, "list-roots.json"), awsapi.Dump{Service: "organizations", Operation: "ListRoots"})
	c.dump(ctx, filepath.Join(org, "list-policies-scp.json"), awsapi.Dump{Service: "organizations", Operation: "ListPolicies", Input: map[string]string{"Filter": "SERVICE_CONTROL_POLICY"}})
	c.dump(ctx, filepath.Join(org, "list-policies-tag.json"), awsapi.Dump{Service: "organizations", Operation: "ListPolicies", Input: map[string]string{"Filter": "TAG_POLICY"}})
	c.dump(ctx, filepath.Join(org, "list-policies-backup.json"), awsapi.Dump{Service: "organizations", Operation: "ListPolicies", Input: map[string]string{"Filter": "BACKUP_POLICY"}})
	c.dump(ctx, filepath.Join(org, "list-delegated-services.json"), awsapi.Dump{Service: "organizations", Operation: "ListDelegatedServicesForAccount", Input: map[string]string{"AccountId": c.account}})

	acct := filepath.Join(g, "account")
	c.dump(ctx, filepath.Join(acct, "contact-info.json"), awsapi.Dump{Service: "account", Operation: "GetContactInformation"})
	for _, t := range []string{"BILLING", "OPERATIONS", "SECURITY"} {
		c.dump(ctx, filepath.Join(acct, "alternate-contact-"+t+".json"), awsapi.Dump{Service: "account", Operation: "GetAlternateContact", Input: map[string]string{"AlternateContactType": t}})
	}
	c.dump(ctx, filepath.Join(acct, "regions.json"), awsapi.Dump{Region: c.home, Service: "account", Operation: "ListRegions"})

	s3 := filepath.Join(g, "s3")
	buckets := c.dump(ctx, filepath.Join(s3, "list-buckets.json"), awsapi.Dump{Service: "s3", Operation: "ListBuckets"})
	c.dump(ctx, filepath.Join(s3, "public-access-block.json"), awsapi.Dump{Service: "s3control", Operation: "GetPublicAccessBlock", Input: map[string]string{"AccountId": c.account}})
	for _, name := range fieldList(buckets, "Buckets", "Name") {
		bd := filepath.Join(s3, "buckets", sanitize(name))
		in := map[string]string{"Bucket": name}
		for _, op := range []struct{ file, op string }{
			{"location.json", "GetBucketLocation"},
			{"acl.json", "GetBucketAcl"},
			{"policy-status.json", "GetBucketPolicyStatus"},
			{"policy.json", "GetBucketPolicy"},
			{"public-access-block.json", "GetBucketPublicAccessBlock"},
			{"encryption.json", "GetBucketEncryption"},
			{"versioning.json", "GetBucketVersioning"},
			{"logging.json", "GetBucketLogging"},
			{"lifecycle.json", "GetBucketLifecycleConfiguration"},
			{"replication.json", "GetBucketReplication"},
			{"website.json", "GetBucketWebsite"},
			{"cors.json", "GetBucketCors"},
			{"tagging.json", "GetBucketTagging"},
			{"ownership-controls.json", "GetBucketOwnershipControls"},
			{"object-lock-configuration.json", "GetObjectLockConfiguration"},
		} {
			c.dump(ctx, filepath.Join(bd, op.file), awsapi.Dump{Service: "s3", Operation: op.op, Input: in})
		}
	}

	r53 := filepath.Join(g, "route53")
	zones := c.dump(ctx, filepath.Join(r53, "hosted-zones.json"), awsapi.Dump{Service: "route53", Operation: "ListHostedZones"})
	c.dump(ctx, filepath.Join(r53, "health-checks.json"), awsapi.Dump{Service: "route53", Operation: "ListHealthChecks"})
	c.dump(ctx, filepath.Join(r53, "traffic-policies.json"), awsapi.Dump{Service: "route53", Operation: "ListTrafficPolicies"})
	c.dump(ctx, filepath.Join(r53, "query-logging-configs.json"), awsapi.Dump{Service: "route53", Operation: "ListQueryLoggingConfigs"})
	for _, zid := range fieldList(zones, "HostedZones", "Id") {
		zid = strings.TrimPrefix(zid, "/hostedzone/")
		c.dump(ctx, filepath.Join(r53, "zones", sanitize(zid)+"-records.json"), awsapi.Dump{Service: "route53", Operation: "ListResourceRecordSets", Input: map[string]string{"HostedZoneId": zid}})
	}

	cf := filepath.Join(g, "cloudfront")
	c.dump(ctx, filepath.Join(cf, "distributions.json"), awsapi.Dump{Service: "cloudfront", Operation: "ListDistributions"})
	c.dump(ctx, filepath.Join(cf, "origin-access-identities.json"), awsapi.Dump{Service: "cloudfront", Operation: "ListCloudFrontOriginAccessIdentities"})
	c.dump(ctx, filepath.Join(cf, "origin-access-controls.json"), awsapi.Dump{Service: "cloudfront", Operation: "ListOriginAccessControls"})
	c.dump(ctx, filepath.Join(cf, "functions.json"), awsapi.Dump{Service: "cloudfront", Operation: "ListFunctions"})
	c.dump(ctx, filepath.Join(cf, "cache-policies.json"), awsapi.Dump{Service: "cloudfront", Operation: "ListCachePolicies"})

	waf := filepath.Join(g, "waf")
	c.dump(ctx, filepath.Join(waf, "cloudfront-web-acls.json"), awsapi.Dump{Region: c.home, Service: "wafv2", Operation: "ListWebACLs", Input: map[string]string{"Scope": "CLOUDFRONT"}})
	c.dump(ctx, filepath.Join(waf, "cloudfront-ip-sets.json"), awsapi.Dump{Region: c.home, Service: "wafv2", Operation: "ListIPSets", Input: map[string]string{"Scope": "CLOUDFRONT"}})

	c.dump(ctx, filepath.Join(g, "support", "trusted-advisor-checks.json"), awsapi.Dump{Service: "support", Operation: "DescribeTrustedAdvisorChecks", Input: map[string]string{"Language": "en"}})
}

func (c *collector) auditRegions(ctx context.Context, scanned []string) {
	sem := make(chan struct{}, c.opts.Parallel)
	var wg sync.WaitGroup
	for _, region := range scanned {
		region := region
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			c.auditRegion(ctx, region)
		}()
	}
	wg.Wait()
}

func (c *collector) auditRegion(ctx context.Context, region string) {
	rd := filepath.Join(c.opts.OutDir, "regions", region)
	d := func(rel string, svc, op string, in map[string]string) json.RawMessage {
		return c.dump(ctx, filepath.Join(rd, rel), awsapi.Dump{Region: region, Service: svc, Operation: op, Input: in})
	}
	d("ec2/instances.json", "ec2", "DescribeInstances", nil)
	d("ec2/images-owned.json", "ec2", "DescribeImages", map[string]string{"Owners": "self"})
	d("ec2/volumes.json", "ec2", "DescribeVolumes", nil)
	d("ec2/snapshots-owned.json", "ec2", "DescribeSnapshots", map[string]string{"OwnerIds": "self"})
	d("ec2/key-pairs.json", "ec2", "DescribeKeyPairs", nil)
	d("ec2/elastic-ips.json", "ec2", "DescribeAddresses", nil)
	d("ec2/network-interfaces.json", "ec2", "DescribeNetworkInterfaces", nil)
	d("ec2/launch-templates.json", "ec2", "DescribeLaunchTemplates", nil)
	d("ec2/security-groups.json", "ec2", "DescribeSecurityGroups", nil)
	d("ec2/ebs-encryption-default.json", "ec2", "GetEbsEncryptionByDefault", nil)
	d("ec2/instance-types-az.json", "ec2", "DescribeInstanceTypeOfferings", nil)
	d("vpc/vpcs.json", "ec2", "DescribeVpcs", nil)
	d("vpc/subnets.json", "ec2", "DescribeSubnets", nil)
	d("vpc/route-tables.json", "ec2", "DescribeRouteTables", nil)
	d("vpc/internet-gateways.json", "ec2", "DescribeInternetGateways", nil)
	d("vpc/nat-gateways.json", "ec2", "DescribeNatGateways", nil)
	d("vpc/egress-only-igws.json", "ec2", "DescribeEgressOnlyInternetGateways", nil)
	d("vpc/vpc-peerings.json", "ec2", "DescribeVpcPeeringConnections", nil)
	d("vpc/vpc-endpoints.json", "ec2", "DescribeVpcEndpoints", nil)
	d("vpc/network-acls.json", "ec2", "DescribeNetworkAcls", nil)
	d("vpc/flow-logs.json", "ec2", "DescribeFlowLogs", nil)
	d("vpc/transit-gateways.json", "ec2", "DescribeTransitGateways", nil)
	d("vpc/transit-gateway-attachments.json", "ec2", "DescribeTransitGatewayAttachments", nil)
	d("vpc/dhcp-options.json", "ec2", "DescribeDhcpOptions", nil)
	d("vpc/customer-gateways.json", "ec2", "DescribeCustomerGateways", nil)
	d("vpc/vpn-connections.json", "ec2", "DescribeVpnConnections", nil)
	d("vpc/vpn-gateways.json", "ec2", "DescribeVpnGateways", nil)
	d("elb/classic.json", "elb", "DescribeLoadBalancers", nil)
	d("elb/v2.json", "elbv2", "DescribeLoadBalancers", nil)
	d("elb/target-groups.json", "elbv2", "DescribeTargetGroups", nil)
	d("autoscaling/groups.json", "autoscaling", "DescribeAutoScalingGroups", nil)
	d("autoscaling/launch-configurations.json", "autoscaling", "DescribeLaunchConfigurations", nil)
	d("lambda/functions.json", "lambda", "ListFunctions", nil)
	d("lambda/layers.json", "lambda", "ListLayers", nil)
	d("lambda/event-source-mappings.json", "lambda", "ListEventSourceMappings", nil)
	d("ecs/clusters.json", "ecs", "ListClusters", nil)
	d("ecs/task-definitions.json", "ecs", "ListTaskDefinitions", nil)
	d("eks/clusters.json", "eks", "ListClusters", nil)
	d("ecr/repositories.json", "ecr", "DescribeRepositories", nil)
	d("rds/instances.json", "rds", "DescribeDBInstances", nil)
	d("rds/clusters.json", "rds", "DescribeDBClusters", nil)
	d("rds/snapshots.json", "rds", "DescribeDBSnapshots", nil)
	d("rds/cluster-snapshots.json", "rds", "DescribeDBClusterSnapshots", nil)
	d("rds/subnet-groups.json", "rds", "DescribeDBSubnetGroups", nil)
	d("rds/parameter-groups.json", "rds", "DescribeDBParameterGroups", nil)
	d("dynamodb/tables.json", "dynamodb", "ListTables", nil)
	d("elasticache/clusters.json", "elasticache", "DescribeCacheClusters", nil)
	d("elasticache/replication-groups.json", "elasticache", "DescribeReplicationGroups", nil)
	d("redshift/clusters.json", "redshift", "DescribeClusters", nil)
	d("opensearch/domains.json", "opensearch", "ListDomainNames", nil)
	d("efs/file-systems.json", "efs", "DescribeFileSystems", nil)
	d("fsx/file-systems.json", "fsx", "DescribeFileSystems", nil)
	d("backup/vaults.json", "backup", "ListBackupVaults", nil)
	d("backup/plans.json", "backup", "ListBackupPlans", nil)
	keys := d("kms/keys.json", "kms", "ListKeys", nil)
	d("kms/aliases.json", "kms", "ListAliases", nil)
	for _, kid := range fieldList(keys, "Keys", "KeyId") {
		in := map[string]string{"KeyId": kid}
		d("kms/keys/"+sanitize(kid)+"-describe.json", "kms", "DescribeKey", in)
		d("kms/keys/"+sanitize(kid)+"-rotation.json", "kms", "GetKeyRotationStatus", in)
		d("kms/keys/"+sanitize(kid)+"-policy.json", "kms", "GetKeyPolicy", map[string]string{"KeyId": kid, "PolicyName": "default"})
	}
	d("secretsmanager/secrets.json", "secretsmanager", "ListSecrets", nil)
	d("ssm/parameters.json", "ssm", "DescribeParameters", nil)
	d("ssm/maintenance-windows.json", "ssm", "DescribeMaintenanceWindows", nil)
	d("ssm/patch-baselines.json", "ssm", "DescribePatchBaselines", nil)
	trails := d("security/cloudtrail-trails.json", "cloudtrail", "DescribeTrails", nil)
	d("security/cloudtrail-eventbuses.json", "cloudtrail", "ListEventDataStores", nil)
	d("security/config-recorders.json", "config", "DescribeConfigurationRecorders", nil)
	d("security/config-recorder-status.json", "config", "DescribeConfigurationRecorderStatus", nil)
	d("security/config-delivery-channels.json", "config", "DescribeDeliveryChannels", nil)
	d("security/guardduty-detectors.json", "guardduty", "ListDetectors", nil)
	d("security/securityhub-hub.json", "securityhub", "DescribeHub", nil)
	d("security/inspector2-status.json", "inspector2", "BatchGetAccountStatus", map[string]string{"AccountIds": c.account})
	d("security/macie-session.json", "macie2", "GetMacieSession", nil)
	d("security/access-analyzer-analyzers.json", "accessanalyzer", "ListAnalyzers", nil)
	d("security/detective-graphs.json", "detective", "ListGraphs", nil)
	for _, name := range fieldList(trails, "trailList", "Name") {
		d("security/trails/"+sanitize(name)+"-status.json", "cloudtrail", "GetTrailStatus", map[string]string{"Name": name})
		d("security/trails/"+sanitize(name)+"-event-selectors.json", "cloudtrail", "GetEventSelectors", map[string]string{"TrailName": name})
	}
	d("logs/log-groups.json", "logs", "DescribeLogGroups", nil)
	d("logs/metric-filters.json", "logs", "DescribeMetricFilters", nil)
	d("logs/destinations.json", "logs", "DescribeDestinations", nil)
	d("sns/topics.json", "sns", "ListTopics", nil)
	d("sqs/queues.json", "sqs", "ListQueues", nil)
	d("events/event-buses.json", "events", "ListEventBuses", nil)
	d("events/rules.json", "events", "ListRules", nil)
	d("apigw/rest-apis.json", "apigateway", "GetRestApis", nil)
	d("apigw/apis-v2.json", "apigatewayv2", "GetApis", nil)
	d("apigw/domain-names.json", "apigateway", "GetDomainNames", nil)
	certs := d("acm/certificates.json", "acm", "ListCertificates", nil)
	for _, arn := range fieldList(certs, "CertificateSummaryList", "CertificateArn") {
		id := arn
		if i := strings.LastIndex(arn, "/"); i >= 0 {
			id = arn[i+1:]
		}
		d("acm/cert-"+sanitize(id)+".json", "acm", "DescribeCertificate", map[string]string{"CertificateArn": arn})
	}
	d("waf/web-acls.json", "wafv2", "ListWebACLs", map[string]string{"Scope": "REGIONAL"})
	d("waf/ip-sets.json", "wafv2", "ListIPSets", map[string]string{"Scope": "REGIONAL"})
	d("tags/resources.json", "resourcegroupstaggingapi", "GetResources", nil)
}

func fieldList(raw json.RawMessage, array, field string) []string {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return nil
	}
	arr, _ := doc[array].([]any)
	var out []string
	for _, item := range arr {
		m, _ := item.(map[string]any)
		if s, ok := m[field].(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '/' || r == '\\' || r == 0 {
			b.WriteByte('_')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func writeCredentialCSV(path string, raw json.RawMessage) {
	var doc struct {
		Content string `json:"Content"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Content == "" {
		return
	}
	b, err := base64.StdEncoding.DecodeString(doc.Content)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o600)
}
