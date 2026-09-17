package awsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/accessanalyzer"
	"github.com/aws/aws-sdk-go-v2/service/account"
	accounttypes "github.com/aws/aws-sdk-go-v2/service/account/types"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/detective"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	orgtypes "github.com/aws/aws-sdk-go-v2/service/organizations/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/resourcegroupstaggingapi"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/support"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

// SDK is the production Client backed by aws-sdk-go-v2.
type SDK struct {
	profile string
	mu      sync.Mutex
	cfgs    map[string]aws.Config
}

// NewSDK loads shared config for profile (no network until the first API call).
func NewSDK(ctx context.Context, profile string) (*SDK, error) {
	s := &SDK{profile: profile, cfgs: map[string]aws.Config{}}
	_, err := s.cfg(ctx, "us-east-1")
	return s, err
}

func (s *SDK) cfg(ctx context.Context, region string) (aws.Config, error) {
	if region == "" {
		region = "us-east-1"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.cfgs[region]; ok {
		return c, nil
	}
	c, err := config.LoadDefaultConfig(ctx,
		config.WithSharedConfigProfile(s.profile),
		config.WithRegion(region),
	)
	if err != nil {
		return aws.Config{}, err
	}
	s.cfgs[region] = c
	return c, nil
}

func (s *SDK) CallerIdentity(ctx context.Context) (Identity, error) {
	cfg, err := s.cfg(ctx, "us-east-1")
	if err != nil {
		return Identity{}, err
	}
	out, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, err
	}
	return Identity{Account: aws.ToString(out.Account), ARN: aws.ToString(out.Arn)}, nil
}

func (s *SDK) ListAccountRegions(ctx context.Context, homeRegion string) ([]RegionStatus, error) {
	cfg, err := s.cfg(ctx, homeRegion)
	if err != nil {
		return nil, err
	}
	var out []RegionStatus
	p := account.NewListRegionsPaginator(account.NewFromConfig(cfg), &account.ListRegionsInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Regions {
			out = append(out, RegionStatus{Name: aws.ToString(r.RegionName), Status: string(r.RegionOptStatus)})
		}
	}
	return out, nil
}

func (s *SDK) EC2DescribeEnabledRegions(ctx context.Context, homeRegion string) ([]string, error) {
	cfg, err := s.cfg(ctx, homeRegion)
	if err != nil {
		return nil, err
	}
	out, err := ec2.NewFromConfig(cfg).DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(true),
		Filters: []ec2types.Filter{{
			Name:   aws.String("opt-in-status"),
			Values: []string{"opt-in-not-required", "opted-in"},
		}},
	})
	if err != nil {
		return nil, err
	}
	var names []string
	for _, r := range out.Regions {
		names = append(names, aws.ToString(r.RegionName))
	}
	return names, nil
}

func (s *SDK) Dump(ctx context.Context, req Dump) (json.RawMessage, error) {
	cfg, err := s.cfg(ctx, req.Region)
	if err != nil {
		return nil, err
	}
	in := req.Input
	if in == nil {
		in = map[string]string{}
	}
	key := req.Service + "." + req.Operation
	switch key {
	case "sts.GetCallerIdentity":
		return marshal(sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}))
	case "iam.GetAccountSummary":
		return marshal(iam.NewFromConfig(cfg).GetAccountSummary(ctx, &iam.GetAccountSummaryInput{}))
	case "iam.GetAccountPasswordPolicy":
		return marshal(iam.NewFromConfig(cfg).GetAccountPasswordPolicy(ctx, &iam.GetAccountPasswordPolicyInput{}))
	case "iam.GetAccountAuthorizationDetails":
		return marshal(iam.NewFromConfig(cfg).GetAccountAuthorizationDetails(ctx, &iam.GetAccountAuthorizationDetailsInput{}))
	case "iam.ListUsers":
		return marshal(iam.NewFromConfig(cfg).ListUsers(ctx, &iam.ListUsersInput{}))
	case "iam.ListRoles":
		return marshal(iam.NewFromConfig(cfg).ListRoles(ctx, &iam.ListRolesInput{}))
	case "iam.ListGroups":
		return marshal(iam.NewFromConfig(cfg).ListGroups(ctx, &iam.ListGroupsInput{}))
	case "iam.ListPolicies":
		return marshal(iam.NewFromConfig(cfg).ListPolicies(ctx, &iam.ListPoliciesInput{Scope: iamtypes.PolicyScopeTypeLocal}))
	case "iam.ListInstanceProfiles":
		return marshal(iam.NewFromConfig(cfg).ListInstanceProfiles(ctx, &iam.ListInstanceProfilesInput{}))
	case "iam.ListSAMLProviders":
		return marshal(iam.NewFromConfig(cfg).ListSAMLProviders(ctx, &iam.ListSAMLProvidersInput{}))
	case "iam.ListOpenIDConnectProviders":
		return marshal(iam.NewFromConfig(cfg).ListOpenIDConnectProviders(ctx, &iam.ListOpenIDConnectProvidersInput{}))
	case "iam.ListServerCertificates":
		return marshal(iam.NewFromConfig(cfg).ListServerCertificates(ctx, &iam.ListServerCertificatesInput{}))
	case "iam.ListVirtualMFADevices":
		return marshal(iam.NewFromConfig(cfg).ListVirtualMFADevices(ctx, &iam.ListVirtualMFADevicesInput{}))
	case "iam.GenerateCredentialReport":
		return marshal(iam.NewFromConfig(cfg).GenerateCredentialReport(ctx, &iam.GenerateCredentialReportInput{}))
	case "iam.GetCredentialReport":
		return marshal(iam.NewFromConfig(cfg).GetCredentialReport(ctx, &iam.GetCredentialReportInput{}))
	case "iam.ListMFADevices":
		return marshal(iam.NewFromConfig(cfg).ListMFADevices(ctx, &iam.ListMFADevicesInput{UserName: aws.String(in["UserName"])}))
	case "iam.ListAccessKeys":
		return marshal(iam.NewFromConfig(cfg).ListAccessKeys(ctx, &iam.ListAccessKeysInput{UserName: aws.String(in["UserName"])}))
	case "iam.ListAttachedUserPolicies":
		return marshal(iam.NewFromConfig(cfg).ListAttachedUserPolicies(ctx, &iam.ListAttachedUserPoliciesInput{UserName: aws.String(in["UserName"])}))
	case "iam.ListUserPolicies":
		return marshal(iam.NewFromConfig(cfg).ListUserPolicies(ctx, &iam.ListUserPoliciesInput{UserName: aws.String(in["UserName"])}))
	case "iam.ListGroupsForUser":
		return marshal(iam.NewFromConfig(cfg).ListGroupsForUser(ctx, &iam.ListGroupsForUserInput{UserName: aws.String(in["UserName"])}))
	case "iam.GetAccessKeyLastUsed":
		return marshal(iam.NewFromConfig(cfg).GetAccessKeyLastUsed(ctx, &iam.GetAccessKeyLastUsedInput{AccessKeyId: aws.String(in["AccessKeyId"])}))
	case "iam.GetRole":
		return marshal(iam.NewFromConfig(cfg).GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(in["RoleName"])}))
	case "iam.ListAttachedRolePolicies":
		return marshal(iam.NewFromConfig(cfg).ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(in["RoleName"])}))
	case "iam.ListRolePolicies":
		return marshal(iam.NewFromConfig(cfg).ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(in["RoleName"])}))
	case "organizations.DescribeOrganization":
		return marshal(organizations.NewFromConfig(cfg).DescribeOrganization(ctx, &organizations.DescribeOrganizationInput{}))
	case "organizations.ListAccounts":
		return marshal(organizations.NewFromConfig(cfg).ListAccounts(ctx, &organizations.ListAccountsInput{}))
	case "organizations.ListRoots":
		return marshal(organizations.NewFromConfig(cfg).ListRoots(ctx, &organizations.ListRootsInput{}))
	case "organizations.ListPolicies":
		return marshal(organizations.NewFromConfig(cfg).ListPolicies(ctx, &organizations.ListPoliciesInput{Filter: orgtypes.PolicyType(in["Filter"])}))
	case "organizations.ListDelegatedServicesForAccount":
		return marshal(organizations.NewFromConfig(cfg).ListDelegatedServicesForAccount(ctx, &organizations.ListDelegatedServicesForAccountInput{AccountId: aws.String(in["AccountId"])}))
	case "account.GetContactInformation":
		return marshal(account.NewFromConfig(cfg).GetContactInformation(ctx, &account.GetContactInformationInput{}))
	case "account.GetAlternateContact":
		return marshal(account.NewFromConfig(cfg).GetAlternateContact(ctx, &account.GetAlternateContactInput{AlternateContactType: accounttypes.AlternateContactType(in["AlternateContactType"])}))
	case "account.ListRegions":
		return marshal(account.NewFromConfig(cfg).ListRegions(ctx, &account.ListRegionsInput{}))
	case "s3.ListBuckets":
		return marshal(s3.NewFromConfig(cfg).ListBuckets(ctx, &s3.ListBucketsInput{}))
	case "s3control.GetPublicAccessBlock":
		return marshal(s3control.NewFromConfig(cfg).GetPublicAccessBlock(ctx, &s3control.GetPublicAccessBlockInput{AccountId: aws.String(in["AccountId"])}))
	case "s3.GetBucketLocation":
		return marshal(s3.NewFromConfig(cfg).GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketAcl":
		return marshal(s3.NewFromConfig(cfg).GetBucketAcl(ctx, &s3.GetBucketAclInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketPolicyStatus":
		return marshal(s3.NewFromConfig(cfg).GetBucketPolicyStatus(ctx, &s3.GetBucketPolicyStatusInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketPolicy":
		return marshal(s3.NewFromConfig(cfg).GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketPublicAccessBlock":
		return marshal(s3.NewFromConfig(cfg).GetPublicAccessBlock(ctx, &s3.GetPublicAccessBlockInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketEncryption":
		return marshal(s3.NewFromConfig(cfg).GetBucketEncryption(ctx, &s3.GetBucketEncryptionInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketVersioning":
		return marshal(s3.NewFromConfig(cfg).GetBucketVersioning(ctx, &s3.GetBucketVersioningInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketLogging":
		return marshal(s3.NewFromConfig(cfg).GetBucketLogging(ctx, &s3.GetBucketLoggingInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketLifecycleConfiguration":
		return marshal(s3.NewFromConfig(cfg).GetBucketLifecycleConfiguration(ctx, &s3.GetBucketLifecycleConfigurationInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketReplication":
		return marshal(s3.NewFromConfig(cfg).GetBucketReplication(ctx, &s3.GetBucketReplicationInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketWebsite":
		return marshal(s3.NewFromConfig(cfg).GetBucketWebsite(ctx, &s3.GetBucketWebsiteInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketCors":
		return marshal(s3.NewFromConfig(cfg).GetBucketCors(ctx, &s3.GetBucketCorsInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketTagging":
		return marshal(s3.NewFromConfig(cfg).GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetBucketOwnershipControls":
		return marshal(s3.NewFromConfig(cfg).GetBucketOwnershipControls(ctx, &s3.GetBucketOwnershipControlsInput{Bucket: aws.String(in["Bucket"])}))
	case "s3.GetObjectLockConfiguration":
		return marshal(s3.NewFromConfig(cfg).GetObjectLockConfiguration(ctx, &s3.GetObjectLockConfigurationInput{Bucket: aws.String(in["Bucket"])}))
	case "route53.ListHostedZones":
		return marshal(route53.NewFromConfig(cfg).ListHostedZones(ctx, &route53.ListHostedZonesInput{}))
	case "route53.ListHealthChecks":
		return marshal(route53.NewFromConfig(cfg).ListHealthChecks(ctx, &route53.ListHealthChecksInput{}))
	case "route53.ListTrafficPolicies":
		return marshal(route53.NewFromConfig(cfg).ListTrafficPolicies(ctx, &route53.ListTrafficPoliciesInput{}))
	case "route53.ListQueryLoggingConfigs":
		return marshal(route53.NewFromConfig(cfg).ListQueryLoggingConfigs(ctx, &route53.ListQueryLoggingConfigsInput{}))
	case "route53.ListResourceRecordSets":
		return marshal(route53.NewFromConfig(cfg).ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{HostedZoneId: aws.String(in["HostedZoneId"])}))
	case "cloudfront.ListDistributions":
		return marshal(cloudfront.NewFromConfig(cfg).ListDistributions(ctx, &cloudfront.ListDistributionsInput{}))
	case "cloudfront.ListCloudFrontOriginAccessIdentities":
		return marshal(cloudfront.NewFromConfig(cfg).ListCloudFrontOriginAccessIdentities(ctx, &cloudfront.ListCloudFrontOriginAccessIdentitiesInput{}))
	case "cloudfront.ListOriginAccessControls":
		return marshal(cloudfront.NewFromConfig(cfg).ListOriginAccessControls(ctx, &cloudfront.ListOriginAccessControlsInput{}))
	case "cloudfront.ListFunctions":
		return marshal(cloudfront.NewFromConfig(cfg).ListFunctions(ctx, &cloudfront.ListFunctionsInput{}))
	case "cloudfront.ListCachePolicies":
		return marshal(cloudfront.NewFromConfig(cfg).ListCachePolicies(ctx, &cloudfront.ListCachePoliciesInput{}))
	case "wafv2.ListWebACLs":
		return marshal(wafv2.NewFromConfig(cfg).ListWebACLs(ctx, &wafv2.ListWebACLsInput{Scope: wafv2types.Scope(in["Scope"])}))
	case "wafv2.ListIPSets":
		return marshal(wafv2.NewFromConfig(cfg).ListIPSets(ctx, &wafv2.ListIPSetsInput{Scope: wafv2types.Scope(in["Scope"])}))
	case "support.DescribeTrustedAdvisorChecks":
		return marshal(support.NewFromConfig(cfg).DescribeTrustedAdvisorChecks(ctx, &support.DescribeTrustedAdvisorChecksInput{Language: aws.String(in["Language"])}))
	case "ec2.DescribeInstances":
		return marshal(ec2.NewFromConfig(cfg).DescribeInstances(ctx, &ec2.DescribeInstancesInput{}))
	case "ec2.DescribeImages":
		return marshal(ec2.NewFromConfig(cfg).DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{in["Owners"]}}))
	case "ec2.DescribeVolumes":
		return marshal(ec2.NewFromConfig(cfg).DescribeVolumes(ctx, &ec2.DescribeVolumesInput{}))
	case "ec2.DescribeSnapshots":
		return marshal(ec2.NewFromConfig(cfg).DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{OwnerIds: []string{in["OwnerIds"]}}))
	case "ec2.DescribeKeyPairs":
		return marshal(ec2.NewFromConfig(cfg).DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{}))
	case "ec2.DescribeAddresses":
		return marshal(ec2.NewFromConfig(cfg).DescribeAddresses(ctx, &ec2.DescribeAddressesInput{}))
	case "ec2.DescribeNetworkInterfaces":
		return marshal(ec2.NewFromConfig(cfg).DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{}))
	case "ec2.DescribeLaunchTemplates":
		return marshal(ec2.NewFromConfig(cfg).DescribeLaunchTemplates(ctx, &ec2.DescribeLaunchTemplatesInput{}))
	case "ec2.DescribeSecurityGroups":
		return marshal(ec2.NewFromConfig(cfg).DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{}))
	case "ec2.GetEbsEncryptionByDefault":
		return marshal(ec2.NewFromConfig(cfg).GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{}))
	case "ec2.DescribeInstanceTypeOfferings":
		return marshal(ec2.NewFromConfig(cfg).DescribeInstanceTypeOfferings(ctx, &ec2.DescribeInstanceTypeOfferingsInput{}))
	case "ec2.DescribeVpcs":
		return marshal(ec2.NewFromConfig(cfg).DescribeVpcs(ctx, &ec2.DescribeVpcsInput{}))
	case "ec2.DescribeSubnets":
		return marshal(ec2.NewFromConfig(cfg).DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{}))
	case "ec2.DescribeRouteTables":
		return marshal(ec2.NewFromConfig(cfg).DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{}))
	case "ec2.DescribeInternetGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeInternetGateways(ctx, &ec2.DescribeInternetGatewaysInput{}))
	case "ec2.DescribeNatGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{}))
	case "ec2.DescribeEgressOnlyInternetGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeEgressOnlyInternetGateways(ctx, &ec2.DescribeEgressOnlyInternetGatewaysInput{}))
	case "ec2.DescribeVpcPeeringConnections":
		return marshal(ec2.NewFromConfig(cfg).DescribeVpcPeeringConnections(ctx, &ec2.DescribeVpcPeeringConnectionsInput{}))
	case "ec2.DescribeVpcEndpoints":
		return marshal(ec2.NewFromConfig(cfg).DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{}))
	case "ec2.DescribeNetworkAcls":
		return marshal(ec2.NewFromConfig(cfg).DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{}))
	case "ec2.DescribeFlowLogs":
		return marshal(ec2.NewFromConfig(cfg).DescribeFlowLogs(ctx, &ec2.DescribeFlowLogsInput{}))
	case "ec2.DescribeTransitGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeTransitGateways(ctx, &ec2.DescribeTransitGatewaysInput{}))
	case "ec2.DescribeTransitGatewayAttachments":
		return marshal(ec2.NewFromConfig(cfg).DescribeTransitGatewayAttachments(ctx, &ec2.DescribeTransitGatewayAttachmentsInput{}))
	case "ec2.DescribeDhcpOptions":
		return marshal(ec2.NewFromConfig(cfg).DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{}))
	case "ec2.DescribeCustomerGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeCustomerGateways(ctx, &ec2.DescribeCustomerGatewaysInput{}))
	case "ec2.DescribeVpnConnections":
		return marshal(ec2.NewFromConfig(cfg).DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{}))
	case "ec2.DescribeVpnGateways":
		return marshal(ec2.NewFromConfig(cfg).DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{}))
	case "elb.DescribeLoadBalancers":
		return marshal(elasticloadbalancing.NewFromConfig(cfg).DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{}))
	case "elbv2.DescribeLoadBalancers":
		return marshal(elasticloadbalancingv2.NewFromConfig(cfg).DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{}))
	case "elbv2.DescribeTargetGroups":
		return marshal(elasticloadbalancingv2.NewFromConfig(cfg).DescribeTargetGroups(ctx, &elasticloadbalancingv2.DescribeTargetGroupsInput{}))
	case "autoscaling.DescribeAutoScalingGroups":
		return marshal(autoscaling.NewFromConfig(cfg).DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{}))
	case "autoscaling.DescribeLaunchConfigurations":
		return marshal(autoscaling.NewFromConfig(cfg).DescribeLaunchConfigurations(ctx, &autoscaling.DescribeLaunchConfigurationsInput{}))
	case "lambda.ListFunctions":
		return marshal(lambda.NewFromConfig(cfg).ListFunctions(ctx, &lambda.ListFunctionsInput{}))
	case "lambda.ListLayers":
		return marshal(lambda.NewFromConfig(cfg).ListLayers(ctx, &lambda.ListLayersInput{}))
	case "lambda.ListEventSourceMappings":
		return marshal(lambda.NewFromConfig(cfg).ListEventSourceMappings(ctx, &lambda.ListEventSourceMappingsInput{}))
	case "ecs.ListClusters":
		return marshal(ecs.NewFromConfig(cfg).ListClusters(ctx, &ecs.ListClustersInput{}))
	case "ecs.ListTaskDefinitions":
		return marshal(ecs.NewFromConfig(cfg).ListTaskDefinitions(ctx, &ecs.ListTaskDefinitionsInput{}))
	case "eks.ListClusters":
		return marshal(eks.NewFromConfig(cfg).ListClusters(ctx, &eks.ListClustersInput{}))
	case "ecr.DescribeRepositories":
		return marshal(ecr.NewFromConfig(cfg).DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{}))
	case "rds.DescribeDBInstances":
		return marshal(rds.NewFromConfig(cfg).DescribeDBInstances(ctx, &rds.DescribeDBInstancesInput{}))
	case "rds.DescribeDBClusters":
		return marshal(rds.NewFromConfig(cfg).DescribeDBClusters(ctx, &rds.DescribeDBClustersInput{}))
	case "rds.DescribeDBSnapshots":
		return marshal(rds.NewFromConfig(cfg).DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{}))
	case "rds.DescribeDBClusterSnapshots":
		return marshal(rds.NewFromConfig(cfg).DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{}))
	case "rds.DescribeDBSubnetGroups":
		return marshal(rds.NewFromConfig(cfg).DescribeDBSubnetGroups(ctx, &rds.DescribeDBSubnetGroupsInput{}))
	case "rds.DescribeDBParameterGroups":
		return marshal(rds.NewFromConfig(cfg).DescribeDBParameterGroups(ctx, &rds.DescribeDBParameterGroupsInput{}))
	case "dynamodb.ListTables":
		return marshal(dynamodb.NewFromConfig(cfg).ListTables(ctx, &dynamodb.ListTablesInput{}))
	case "elasticache.DescribeCacheClusters":
		return marshal(elasticache.NewFromConfig(cfg).DescribeCacheClusters(ctx, &elasticache.DescribeCacheClustersInput{}))
	case "elasticache.DescribeReplicationGroups":
		return marshal(elasticache.NewFromConfig(cfg).DescribeReplicationGroups(ctx, &elasticache.DescribeReplicationGroupsInput{}))
	case "redshift.DescribeClusters":
		return marshal(redshift.NewFromConfig(cfg).DescribeClusters(ctx, &redshift.DescribeClustersInput{}))
	case "opensearch.ListDomainNames":
		return marshal(opensearch.NewFromConfig(cfg).ListDomainNames(ctx, &opensearch.ListDomainNamesInput{}))
	case "efs.DescribeFileSystems":
		return marshal(efs.NewFromConfig(cfg).DescribeFileSystems(ctx, &efs.DescribeFileSystemsInput{}))
	case "fsx.DescribeFileSystems":
		return marshal(fsx.NewFromConfig(cfg).DescribeFileSystems(ctx, &fsx.DescribeFileSystemsInput{}))
	case "backup.ListBackupVaults":
		return marshal(backup.NewFromConfig(cfg).ListBackupVaults(ctx, &backup.ListBackupVaultsInput{}))
	case "backup.ListBackupPlans":
		return marshal(backup.NewFromConfig(cfg).ListBackupPlans(ctx, &backup.ListBackupPlansInput{}))
	case "kms.ListKeys":
		return marshal(kms.NewFromConfig(cfg).ListKeys(ctx, &kms.ListKeysInput{}))
	case "kms.ListAliases":
		return marshal(kms.NewFromConfig(cfg).ListAliases(ctx, &kms.ListAliasesInput{}))
	case "kms.DescribeKey":
		return marshal(kms.NewFromConfig(cfg).DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: aws.String(in["KeyId"])}))
	case "kms.GetKeyRotationStatus":
		return marshal(kms.NewFromConfig(cfg).GetKeyRotationStatus(ctx, &kms.GetKeyRotationStatusInput{KeyId: aws.String(in["KeyId"])}))
	case "kms.GetKeyPolicy":
		return marshal(kms.NewFromConfig(cfg).GetKeyPolicy(ctx, &kms.GetKeyPolicyInput{KeyId: aws.String(in["KeyId"]), PolicyName: aws.String(in["PolicyName"])}))
	case "secretsmanager.ListSecrets":
		return marshal(secretsmanager.NewFromConfig(cfg).ListSecrets(ctx, &secretsmanager.ListSecretsInput{}))
	case "ssm.DescribeParameters":
		return marshal(ssm.NewFromConfig(cfg).DescribeParameters(ctx, &ssm.DescribeParametersInput{}))
	case "ssm.DescribeMaintenanceWindows":
		return marshal(ssm.NewFromConfig(cfg).DescribeMaintenanceWindows(ctx, &ssm.DescribeMaintenanceWindowsInput{}))
	case "ssm.DescribePatchBaselines":
		return marshal(ssm.NewFromConfig(cfg).DescribePatchBaselines(ctx, &ssm.DescribePatchBaselinesInput{}))
	case "cloudtrail.DescribeTrails":
		return marshal(cloudtrail.NewFromConfig(cfg).DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{}))
	case "cloudtrail.ListEventDataStores":
		return marshal(cloudtrail.NewFromConfig(cfg).ListEventDataStores(ctx, &cloudtrail.ListEventDataStoresInput{}))
	case "cloudtrail.GetTrailStatus":
		return marshal(cloudtrail.NewFromConfig(cfg).GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{Name: aws.String(in["Name"])}))
	case "cloudtrail.GetEventSelectors":
		return marshal(cloudtrail.NewFromConfig(cfg).GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{TrailName: aws.String(in["TrailName"])}))
	case "config.DescribeConfigurationRecorders":
		return marshal(configservice.NewFromConfig(cfg).DescribeConfigurationRecorders(ctx, &configservice.DescribeConfigurationRecordersInput{}))
	case "config.DescribeConfigurationRecorderStatus":
		return marshal(configservice.NewFromConfig(cfg).DescribeConfigurationRecorderStatus(ctx, &configservice.DescribeConfigurationRecorderStatusInput{}))
	case "config.DescribeDeliveryChannels":
		return marshal(configservice.NewFromConfig(cfg).DescribeDeliveryChannels(ctx, &configservice.DescribeDeliveryChannelsInput{}))
	case "guardduty.ListDetectors":
		return marshal(guardduty.NewFromConfig(cfg).ListDetectors(ctx, &guardduty.ListDetectorsInput{}))
	case "securityhub.DescribeHub":
		return marshal(securityhub.NewFromConfig(cfg).DescribeHub(ctx, &securityhub.DescribeHubInput{}))
	case "inspector2.BatchGetAccountStatus":
		return marshal(inspector2.NewFromConfig(cfg).BatchGetAccountStatus(ctx, &inspector2.BatchGetAccountStatusInput{AccountIds: []string{in["AccountIds"]}}))
	case "macie2.GetMacieSession":
		return marshal(macie2.NewFromConfig(cfg).GetMacieSession(ctx, &macie2.GetMacieSessionInput{}))
	case "accessanalyzer.ListAnalyzers":
		return marshal(accessanalyzer.NewFromConfig(cfg).ListAnalyzers(ctx, &accessanalyzer.ListAnalyzersInput{}))
	case "detective.ListGraphs":
		return marshal(detective.NewFromConfig(cfg).ListGraphs(ctx, &detective.ListGraphsInput{}))
	case "logs.DescribeLogGroups":
		return marshal(cloudwatchlogs.NewFromConfig(cfg).DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{}))
	case "logs.DescribeMetricFilters":
		return marshal(cloudwatchlogs.NewFromConfig(cfg).DescribeMetricFilters(ctx, &cloudwatchlogs.DescribeMetricFiltersInput{}))
	case "logs.DescribeDestinations":
		return marshal(cloudwatchlogs.NewFromConfig(cfg).DescribeDestinations(ctx, &cloudwatchlogs.DescribeDestinationsInput{}))
	case "sns.ListTopics":
		return marshal(sns.NewFromConfig(cfg).ListTopics(ctx, &sns.ListTopicsInput{}))
	case "sqs.ListQueues":
		return marshal(sqs.NewFromConfig(cfg).ListQueues(ctx, &sqs.ListQueuesInput{}))
	case "events.ListEventBuses":
		return marshal(eventbridge.NewFromConfig(cfg).ListEventBuses(ctx, &eventbridge.ListEventBusesInput{}))
	case "events.ListRules":
		return marshal(eventbridge.NewFromConfig(cfg).ListRules(ctx, &eventbridge.ListRulesInput{}))
	case "apigateway.GetRestApis":
		return marshal(apigateway.NewFromConfig(cfg).GetRestApis(ctx, &apigateway.GetRestApisInput{}))
	case "apigatewayv2.GetApis":
		return marshal(apigatewayv2.NewFromConfig(cfg).GetApis(ctx, &apigatewayv2.GetApisInput{}))
	case "apigateway.GetDomainNames":
		return marshal(apigateway.NewFromConfig(cfg).GetDomainNames(ctx, &apigateway.GetDomainNamesInput{}))
	case "acm.ListCertificates":
		return marshal(acm.NewFromConfig(cfg).ListCertificates(ctx, &acm.ListCertificatesInput{}))
	case "acm.DescribeCertificate":
		return marshal(acm.NewFromConfig(cfg).DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: aws.String(in["CertificateArn"])}))
	case "resourcegroupstaggingapi.GetResources":
		return marshal(resourcegroupstaggingapi.NewFromConfig(cfg).GetResources(ctx, &resourcegroupstaggingapi.GetResourcesInput{}))
	default:
		return nil, fmt.Errorf("unmapped AWS operation %s", key)
	}
}

func marshal(v any, err error) (json.RawMessage, error) {
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(v)
	return b, err
}
