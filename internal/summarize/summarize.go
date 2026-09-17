package summarize

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Report reads an aws-audit dump directory and returns markdown findings.
func Report(dir string) (string, error) {
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return "", fmt.Errorf("Usage: aws-audit-summarize <audit-output-dir>")
	}
	g := filepath.Join(dir, "global")
	r := filepath.Join(dir, "regions")
	var b strings.Builder

	account := sj(filepath.Join(dir, "meta.json"), "account_id")
	principal := sj(filepath.Join(dir, "meta.json"), "principal_arn")
	fmt.Fprintf(&b, "# AWS Configuration Audit — Account %s\n\n", account)
	fmt.Fprintf(&b, "- **Principal:** %s\n", principal)
	fmt.Fprintf(&b, "- **Generated:** %s\n", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(&b, "- **Raw data:** `%s`\n\n", dir)
	b.WriteString("> This is an automated read-only audit. Findings below are derived from\n")
	b.WriteString("> AWS API metadata; verify each before acting. Items where the auditing\n")
	b.WriteString("> principal lacked permission appear in `errors.log` and may produce\n")
	b.WriteString("> false negatives.\n")

	iam(g, &b)
	securityServices(r, &b)
	network(r, &b)
	s3(g, &b)
	compute(r, &b)
	kms(r, &b)
	acm(r, &b)
	logging(r, &b)
	cost(r, &b)
	coverage(dir, r, &b)
	inventory(dir, g, r, &b)
	errorsSection(dir, &b)
	return b.String(), nil
}

func section(b *strings.Builder, title string) {
	fmt.Fprintf(b, "\n## %s\n\n", title)
}

func finding(b *strings.Builder, sev, msg string) {
	fmt.Fprintf(b, "- **%s** — %s\n", sev, msg)
}

func note(b *strings.Builder, msg string) {
	fmt.Fprintf(b, "- %s\n", msg)
}

func iam(g string, b *strings.Builder) {
	section(b, "IAM & Identity")
	csvPath := filepath.Join(g, "iam", "credential-report.csv")
	if rows, err := readCSV(csvPath); err == nil && len(rows) > 1 {
		for _, row := range rows[1:] {
			if len(row) < 14 {
				continue
			}
			if row[0] == "<root_account>" {
				if row[7] == "false" {
					finding(b, "HIGH: Root account MFA disabled", "Enable hardware MFA on the root user immediately.")
				}
				if row[8] == "true" {
					finding(b, "HIGH: Root account has active access key #1", "Delete root access keys; the root user should never have programmatic credentials.")
				}
				if row[13] == "true" {
					finding(b, "HIGH: Root account has active access key #2", "Delete root access keys.")
				}
			}
		}
		var noMFA []string
		now := time.Now().UTC()
		var oldKeys []string
		for _, row := range rows[1:] {
			if len(row) < 14 || row[0] == "<root_account>" || row[0] == "user" {
				continue
			}
			if row[3] == "true" && row[7] == "false" {
				noMFA = append(noMFA, row[0])
			}
			checkOld := func(label, active, rotated string) {
				if active != "true" || rotated == "N/A" || rotated == "" {
					return
				}
				t, err := time.Parse(time.RFC3339, strings.Replace(rotated, " ", "T", 1))
				if err != nil {
					t, err = time.Parse("2006-01-02T15:04:05+00:00", strings.Split(rotated, ".")[0]+"+00:00")
				}
				if err != nil {
					return
				}
				days := int(now.Sub(t).Hours() / 24)
				if days > 90 {
					oldKeys = append(oldKeys, fmt.Sprintf("%s (%s, %dd)", row[0], label, days))
				}
			}
			checkOld("ak1", row[8], row[9])
			if len(row) > 14 {
				checkOld("ak2", row[13], row[14])
			}
		}
		if len(noMFA) > 0 {
			finding(b, "MEDIUM: IAM users with console password but no MFA", strings.Join(noMFA, ","))
		}
		if len(oldKeys) > 0 {
			finding(b, "MEDIUM: Access keys older than 90 days", strings.Join(oldKeys, ", "))
		}
	} else {
		note(b, "Credential report not available (permission denied or not generated).")
	}

	pwp := filepath.Join(g, "iam", "account-password-policy.json")
	var pol struct {
		PasswordPolicy *struct {
			MinimumPasswordLength      int  `json:"MinimumPasswordLength"`
			RequireSymbols             bool `json:"RequireSymbols"`
			RequireNumbers             bool `json:"RequireNumbers"`
			RequireUppercaseCharacters bool `json:"RequireUppercaseCharacters"`
			RequireLowercaseCharacters bool `json:"RequireLowercaseCharacters"`
			MaxPasswordAge             int  `json:"MaxPasswordAge"`
			PasswordReusePrevention    int  `json:"PasswordReusePrevention"`
		} `json:"PasswordPolicy"`
	}
	_ = readJSON(pwp, &pol)
	if pol.PasswordPolicy == nil {
		finding(b, "MEDIUM: No IAM password policy set", "Configure an account-wide IAM password policy.")
	} else {
		p := pol.PasswordPolicy
		if p.MinimumPasswordLength < 14 {
			finding(b, fmt.Sprintf("MEDIUM: Password policy min length %d < 14", p.MinimumPasswordLength), "Raise minimum length to at least 14.")
		}
		if !p.RequireSymbols || !p.RequireNumbers || !p.RequireUppercaseCharacters || !p.RequireLowercaseCharacters {
			finding(b, "LOW: Password policy missing character class requirements", "Require symbols, numbers, upper- and lower-case.")
		}
		if p.MaxPasswordAge == 0 || p.MaxPasswordAge > 90 {
			finding(b, fmt.Sprintf("LOW: Password max age %d > 90 (or unset)", p.MaxPasswordAge), "Set max age to 90 days.")
		}
		if p.PasswordReusePrevention < 24 {
			finding(b, fmt.Sprintf("LOW: Password reuse prevention %d < 24", p.PasswordReusePrevention), "Prevent reuse of last 24 passwords.")
		}
	}

	var inline []string
	_ = filepath.Walk(filepath.Join(g, "iam", "users"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Name() != "inline-policies.json" {
			return nil
		}
		var doc struct {
			PolicyNames []string `json:"PolicyNames"`
		}
		if readJSON(path, &doc) == nil && len(doc.PolicyNames) > 0 {
			inline = append(inline, filepath.Base(filepath.Dir(path)))
		}
		return nil
	})
	if len(inline) > 0 {
		finding(b, "LOW: IAM users with inline policies", strings.Join(inline, ",")+" — prefer managed policies and groups.")
	}
}

func securityServices(r string, b *strings.Builder) {
	section(b, "Account-Level Security Services")
	type trail struct {
		Name                     string `json:"Name"`
		IsMultiRegionTrail       bool   `json:"IsMultiRegionTrail"`
		LogFileValidationEnabled bool   `json:"LogFileValidationEnabled"`
		KmsKeyId                 string `json:"KmsKeyId"`
	}
	trails := map[string]trail{}
	for _, f := range glob(r, "*/security/cloudtrail-trails.json") {
		var doc struct {
			TrailList []trail `json:"trailList"`
		}
		_ = readJSON(f, &doc)
		for _, t := range doc.TrailList {
			trails[t.Name] = t
		}
	}
	logging := map[string]bool{}
	for _, f := range glob(r, "*/security/trails/*-status.json") {
		name := strings.TrimSuffix(filepath.Base(f), "-status.json")
		var doc struct {
			IsLogging bool `json:"IsLogging"`
		}
		_ = readJSON(f, &doc)
		if doc.IsLogging {
			logging[name] = true
		} else if _, ok := logging[name]; !ok {
			logging[name] = false
		}
	}
	if len(trails) == 0 {
		finding(b, "HIGH: No CloudTrail trails found", "Enable at least one multi-region CloudTrail with log file validation.")
	} else {
		multi := 0
		var noVal, noKMS, notLog []string
		for _, t := range trails {
			if t.IsMultiRegionTrail {
				multi++
			}
			if !t.LogFileValidationEnabled {
				noVal = append(noVal, t.Name)
			}
			if t.KmsKeyId == "" {
				noKMS = append(noKMS, t.Name)
			}
		}
		for name, on := range logging {
			if !on {
				notLog = append(notLog, name)
			}
		}
		if multi == 0 {
			finding(b, "HIGH: No multi-region CloudTrail", "Convert (or create) a trail with IsMultiRegionTrail=true.")
		}
		if len(noVal) > 0 {
			finding(b, "MEDIUM: CloudTrail without log file validation", strings.Join(noVal, ","))
		}
		if len(noKMS) > 0 {
			finding(b, "LOW: CloudTrail without KMS encryption", strings.Join(noKMS, ","))
		}
		if len(notLog) > 0 {
			finding(b, "HIGH: CloudTrail trails not actively logging", strings.Join(notLog, ","))
		}
	}

	off := regionsWhere(r, "security/guardduty-detectors.json", func(raw []byte) bool {
		var doc struct {
			DetectorIds []string `json:"DetectorIds"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.DetectorIds) == 0
	})
	if len(off) > 0 {
		finding(b, "MEDIUM: GuardDuty disabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(r, "security/config-recorders.json", func(raw []byte) bool {
		var doc struct {
			ConfigurationRecorders []any `json:"ConfigurationRecorders"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.ConfigurationRecorders) == 0
	})
	if len(off) > 0 {
		finding(b, "MEDIUM: AWS Config not enabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(r, "security/securityhub-hub.json", func(raw []byte) bool {
		var doc map[string]any
		_ = json.Unmarshal(raw, &doc)
		_, ok := doc["HubArn"]
		return !ok
	})
	if len(off) > 0 {
		finding(b, "LOW: Security Hub not enabled in regions", strings.Join(off, ","))
	}
	off = regionsWhere(r, "security/access-analyzer-analyzers.json", func(raw []byte) bool {
		var doc struct {
			Analyzers []any `json:"analyzers"`
		}
		_ = json.Unmarshal(raw, &doc)
		return len(doc.Analyzers) == 0
	})
	if len(off) > 0 {
		finding(b, "LOW: IAM Access Analyzer not configured in regions", strings.Join(off, ","))
	}
}

func network(r string, b *strings.Builder) {
	section(b, "Network — Security Groups")
	var open []string
	for _, f := range glob(r, "*/ec2/security-groups.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			SecurityGroups []struct {
				GroupId       string `json:"GroupId"`
				GroupName     string `json:"GroupName"`
				IpPermissions []struct {
					IpProtocol string `json:"IpProtocol"`
					FromPort   *int   `json:"FromPort"`
					ToPort     *int   `json:"ToPort"`
					IpRanges   []struct {
						CidrIp string `json:"CidrIp"`
					} `json:"IpRanges"`
				} `json:"IpPermissions"`
			} `json:"SecurityGroups"`
		}
		_ = readJSON(f, &doc)
		for _, sg := range doc.SecurityGroups {
			for _, p := range sg.IpPermissions {
				for _, ip := range p.IpRanges {
					if ip.CidrIp == "0.0.0.0/0" {
						from, to := "all", "all"
						if p.FromPort != nil {
							from = fmt.Sprintf("%d", *p.FromPort)
						}
						if p.ToPort != nil {
							to = fmt.Sprintf("%d", *p.ToPort)
						}
						open = append(open, fmt.Sprintf("%s  %s (%s)  %s %s-%s", region, sg.GroupId, sg.GroupName, p.IpProtocol, from, to))
					}
				}
			}
		}
	}
	if len(open) > 0 {
		fmt.Fprintf(b, "\n### Security groups with 0.0.0.0/0 ingress\n\n")
		for _, e := range open {
			note(b, "`"+e+"`")
		}
		finding(b, "HIGH: Security groups expose ports to the public internet", "Restrict ingress to specific CIDRs; pay special attention to 22 (SSH), 3389 (RDP), 3306, 5432, 1433, 27017, 6379.")
	}

	var defVPC, noFlow []string
	for _, f := range glob(r, "*/vpc/vpcs.json") {
		region := regionFrom(f, "vpc")
		var doc struct {
			Vpcs []struct {
				VpcId     string `json:"VpcId"`
				IsDefault bool   `json:"IsDefault"`
			} `json:"Vpcs"`
		}
		_ = readJSON(f, &doc)
		var flow struct {
			FlowLogs []struct {
				ResourceId string `json:"ResourceId"`
			} `json:"FlowLogs"`
		}
		_ = readJSON(filepath.Join(filepath.Dir(f), "flow-logs.json"), &flow)
		have := map[string]bool{}
		for _, fl := range flow.FlowLogs {
			have[fl.ResourceId] = true
		}
		for _, v := range doc.Vpcs {
			if v.IsDefault {
				defVPC = append(defVPC, region+"/"+v.VpcId)
			}
			if !have[v.VpcId] {
				noFlow = append(noFlow, region+"/"+v.VpcId)
			}
		}
	}
	if len(defVPC) > 0 {
		finding(b, "LOW: Default VPC present", strings.Join(defVPC, ",")+" — consider deleting unused default VPCs.")
	}
	if len(noFlow) > 0 {
		finding(b, "MEDIUM: VPCs without flow logs", strings.Join(noFlow, ","))
	}
}

func s3(g string, b *strings.Builder) {
	section(b, "S3")
	if !fullPAB(filepath.Join(g, "s3", "public-access-block.json")) {
		finding(b, "HIGH: Account-level S3 Public Access Block not fully enabled", "Enable all four block settings at the account level via s3control.")
	}
	var pub, noPAB, noEnc, noVer, noLog, web []string
	entries, _ := os.ReadDir(filepath.Join(g, "s3", "buckets"))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		bd := filepath.Join(g, "s3", "buckets", e.Name())
		name := e.Name()
		if !fullPAB(filepath.Join(bd, "public-access-block.json")) {
			noPAB = append(noPAB, name)
		}
		var ps struct {
			PolicyStatus struct {
				IsPublic bool `json:"IsPublic"`
			} `json:"PolicyStatus"`
		}
		_ = readJSON(filepath.Join(bd, "policy-status.json"), &ps)
		if ps.PolicyStatus.IsPublic {
			pub = append(pub, name)
		}
		var enc struct {
			ServerSideEncryptionConfiguration struct {
				Rules []any `json:"Rules"`
			} `json:"ServerSideEncryptionConfiguration"`
		}
		_ = readJSON(filepath.Join(bd, "encryption.json"), &enc)
		if len(enc.ServerSideEncryptionConfiguration.Rules) == 0 {
			noEnc = append(noEnc, name)
		}
		if sj(filepath.Join(bd, "versioning.json"), "Status") != "Enabled" {
			noVer = append(noVer, name)
		}
		var log struct {
			LoggingEnabled any `json:"LoggingEnabled"`
		}
		_ = readJSON(filepath.Join(bd, "logging.json"), &log)
		if log.LoggingEnabled == nil {
			noLog = append(noLog, name)
		}
		var site map[string]any
		_ = readJSON(filepath.Join(bd, "website.json"), &site)
		if site["IndexDocument"] != nil || site["RedirectAllRequestsTo"] != nil {
			web = append(web, name)
		}
	}
	if len(pub) > 0 {
		finding(b, "HIGH: S3 buckets resolved as public", strings.Join(pub, ","))
	}
	if len(noPAB) > 0 {
		finding(b, "MEDIUM: S3 buckets without full public access block", strings.Join(noPAB, ","))
	}
	if len(noEnc) > 0 {
		finding(b, "MEDIUM: S3 buckets without default encryption", strings.Join(noEnc, ","))
	}
	if len(noVer) > 0 {
		finding(b, "LOW: S3 buckets without versioning", strings.Join(noVer, ","))
	}
	if len(noLog) > 0 {
		finding(b, "LOW: S3 buckets without access logging", strings.Join(noLog, ","))
	}
	if len(web) > 0 {
		note(b, "Buckets configured for static website hosting: "+strings.Join(web, ","))
	}
}

func fullPAB(path string) bool {
	var doc struct {
		PublicAccessBlockConfiguration struct {
			BlockPublicAcls       bool `json:"BlockPublicAcls"`
			BlockPublicPolicy     bool `json:"BlockPublicPolicy"`
			IgnorePublicAcls      bool `json:"IgnorePublicAcls"`
			RestrictPublicBuckets bool `json:"RestrictPublicBuckets"`
		} `json:"PublicAccessBlockConfiguration"`
	}
	if readJSON(path, &doc) != nil {
		return false
	}
	c := doc.PublicAccessBlockConfiguration
	return c.BlockPublicAcls && c.BlockPublicPolicy && c.IgnorePublicAcls && c.RestrictPublicBuckets
}

func compute(r string, b *strings.Builder) {
	section(b, "Compute & Data — Encryption")
	ebsOff := regionsWhere(r, "ec2/ebs-encryption-default.json", func(raw []byte) bool {
		var doc struct {
			EbsEncryptionByDefault bool `json:"EbsEncryptionByDefault"`
		}
		_ = json.Unmarshal(raw, &doc)
		return !doc.EbsEncryptionByDefault
	})
	if len(ebsOff) > 0 {
		finding(b, "MEDIUM: EBS encryption by default disabled", strings.Join(ebsOff, ",")+" — enable EBS encryption-by-default per region.")
	}
	var unenc, rdsPub, rdsUnenc, rdsNoBackup, publicIP, imds []string
	for _, f := range glob(r, "*/ec2/volumes.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Volumes []struct {
				VolumeId  string `json:"VolumeId"`
				Encrypted bool   `json:"Encrypted"`
			} `json:"Volumes"`
		}
		_ = readJSON(f, &doc)
		for _, v := range doc.Volumes {
			if !v.Encrypted {
				unenc = append(unenc, region+"/"+v.VolumeId)
			}
		}
	}
	if len(unenc) > 0 {
		finding(b, "MEDIUM: Unencrypted EBS volumes", strings.Join(unenc, ","))
	}
	for _, f := range glob(r, "*/rds/instances.json") {
		region := regionFrom(f, "rds")
		var doc struct {
			DBInstances []struct {
				DBInstanceIdentifier  string `json:"DBInstanceIdentifier"`
				PubliclyAccessible    bool   `json:"PubliclyAccessible"`
				StorageEncrypted      bool   `json:"StorageEncrypted"`
				BackupRetentionPeriod int    `json:"BackupRetentionPeriod"`
			} `json:"DBInstances"`
		}
		_ = readJSON(f, &doc)
		for _, d := range doc.DBInstances {
			if d.PubliclyAccessible {
				rdsPub = append(rdsPub, region+"/"+d.DBInstanceIdentifier)
			}
			if !d.StorageEncrypted {
				rdsUnenc = append(rdsUnenc, region+"/"+d.DBInstanceIdentifier)
			}
			if d.BackupRetentionPeriod == 0 {
				rdsNoBackup = append(rdsNoBackup, region+"/"+d.DBInstanceIdentifier)
			}
		}
	}
	if len(rdsPub) > 0 {
		finding(b, "HIGH: Publicly accessible RDS instances", strings.Join(rdsPub, ","))
	}
	if len(rdsUnenc) > 0 {
		finding(b, "HIGH: Unencrypted RDS storage", strings.Join(rdsUnenc, ","))
	}
	if len(rdsNoBackup) > 0 {
		finding(b, "MEDIUM: RDS instances with 0-day backup retention", strings.Join(rdsNoBackup, ","))
	}
	for _, f := range glob(r, "*/ec2/instances.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Reservations []struct {
				Instances []struct {
					InstanceId      string `json:"InstanceId"`
					PublicIpAddress string `json:"PublicIpAddress"`
					State           struct {
						Name string `json:"Name"`
					} `json:"State"`
					MetadataOptions struct {
						HttpTokens string `json:"HttpTokens"`
					} `json:"MetadataOptions"`
				} `json:"Instances"`
			} `json:"Reservations"`
		}
		_ = readJSON(f, &doc)
		for _, res := range doc.Reservations {
			for _, inst := range res.Instances {
				if inst.PublicIpAddress != "" && (inst.State.Name == "running" || inst.State.Name == "pending") {
					publicIP = append(publicIP, fmt.Sprintf("%s/%s (%s)", region, inst.InstanceId, inst.PublicIpAddress))
				}
				if inst.MetadataOptions.HttpTokens != "required" && inst.InstanceId != "" {
					imds = append(imds, region+"/"+inst.InstanceId)
				}
			}
		}
	}
	if len(publicIP) > 0 {
		note(b, "Public-IP EC2 instances: "+strings.Join(publicIP, ",")+" — verify exposure is intentional.")
	}
	if len(imds) > 0 {
		finding(b, "MEDIUM: EC2 instances not enforcing IMDSv2", strings.Join(imds, ","))
	}
}

func kms(r string, b *strings.Builder) {
	section(b, "KMS")
	var no []string
	for _, f := range glob(r, "*/kms/keys/*-rotation.json") {
		region := regionFrom(filepath.Dir(filepath.Dir(f)), "kms")
		key := strings.TrimSuffix(filepath.Base(f), "-rotation.json")
		var doc struct {
			KeyRotationEnabled bool `json:"KeyRotationEnabled"`
		}
		_ = readJSON(f, &doc)
		if !doc.KeyRotationEnabled {
			no = append(no, region+"/"+key)
		}
	}
	if len(no) > 0 {
		finding(b, "LOW: Customer-managed KMS keys without rotation", strings.Join(no, ","))
	}
}

func acm(r string, b *strings.Builder) {
	section(b, "ACM Certificates")
	var exp []string
	now := time.Now().UTC()
	for _, f := range glob(r, "*/acm/cert-*.json") {
		region := regionFrom(f, "acm")
		var doc struct {
			Certificate struct {
				DomainName string `json:"DomainName"`
				NotAfter   string `json:"NotAfter"`
				Status     string `json:"Status"`
			} `json:"Certificate"`
		}
		_ = readJSON(f, &doc)
		if doc.Certificate.NotAfter == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, doc.Certificate.NotAfter)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", strings.Split(doc.Certificate.NotAfter, ".")[0])
		}
		if err != nil {
			continue
		}
		days := int(t.Sub(now).Hours() / 24)
		if days < 30 {
			exp = append(exp, fmt.Sprintf("%s %s expires in %dd (status: %s)", region, doc.Certificate.DomainName, days, doc.Certificate.Status))
		}
	}
	if len(exp) > 0 {
		finding(b, "MEDIUM: ACM certificates expiring soon", strings.Join(exp, "; "))
	}
}

func logging(r string, b *strings.Builder) {
	section(b, "Logging")
	var none []string
	for _, f := range glob(r, "*/logs/log-groups.json") {
		region := regionFrom(f, "logs")
		var doc struct {
			LogGroups []struct {
				LogGroupName    string `json:"logGroupName"`
				RetentionInDays *int   `json:"retentionInDays"`
			} `json:"logGroups"`
		}
		_ = readJSON(f, &doc)
		for _, lg := range doc.LogGroups {
			if lg.RetentionInDays == nil {
				none = append(none, region+"/"+lg.LogGroupName)
			}
		}
	}
	if len(none) > 50 {
		n := 10
		if n > len(none) {
			n = len(none)
		}
		finding(b, fmt.Sprintf("LOW: %d CloudWatch log groups have no retention (never expire)", len(none)), "Set retention on log groups to control cost; sampling first 10: "+strings.Join(none[:n], ","))
	} else if len(none) > 0 {
		finding(b, "LOW: CloudWatch log groups without retention", strings.Join(none, ","))
	}
}

func cost(r string, b *strings.Builder) {
	section(b, "Cost & Governance")
	var unattached, eip []string
	for _, f := range glob(r, "*/ec2/volumes.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Volumes []struct {
				VolumeId   string `json:"VolumeId"`
				State      string `json:"State"`
				Size       int    `json:"Size"`
				VolumeType string `json:"VolumeType"`
			} `json:"Volumes"`
		}
		_ = readJSON(f, &doc)
		for _, v := range doc.Volumes {
			if v.State == "available" {
				unattached = append(unattached, fmt.Sprintf("%s/%s (%dGB %s)", region, v.VolumeId, v.Size, v.VolumeType))
			}
		}
	}
	if len(unattached) > 0 {
		finding(b, "COST: Unattached EBS volumes", strings.Join(unattached, ",")+" — delete if unused.")
	}
	for _, f := range glob(r, "*/ec2/elastic-ips.json") {
		region := regionFrom(f, "ec2")
		var doc struct {
			Addresses []struct {
				PublicIp      string `json:"PublicIp"`
				AssociationId string `json:"AssociationId"`
			} `json:"Addresses"`
		}
		_ = readJSON(f, &doc)
		for _, a := range doc.Addresses {
			if a.AssociationId == "" && a.PublicIp != "" {
				eip = append(eip, region+"/"+a.PublicIp)
			}
		}
	}
	if len(eip) > 0 {
		finding(b, "COST: Unassociated Elastic IPs (charged hourly)", strings.Join(eip, ","))
	}
	untagged := 0
	for _, f := range glob(r, "*/tags/resources.json") {
		var doc struct {
			ResourceTagMappingList []struct {
				Tags []any `json:"Tags"`
			} `json:"ResourceTagMappingList"`
		}
		_ = readJSON(f, &doc)
		for _, m := range doc.ResourceTagMappingList {
			if len(m.Tags) == 0 {
				untagged++
			}
		}
	}
	if untagged > 0 {
		finding(b, fmt.Sprintf("GOVERNANCE: %d resources with no tags", untagged), "Adopt a tagging standard (Owner, Environment, CostCenter) and enforce via SCP or Config rule.")
	}
}

func coverage(dir, r string, b *strings.Builder) {
	section(b, "Region coverage")
	meta := filepath.Join(dir, "meta.json")
	part := sj(meta, "partition")
	home := sj(meta, "home_region")
	if part != "" {
		note(b, fmt.Sprintf("Partition: %s (home Region %s)", part, home))
	}
	var scanned []string
	var raw struct {
		RegionsScanned    []string `json:"regions_scanned"`
		RegionsNotEnabled []string `json:"regions_not_enabled"`
	}
	_ = readJSON(meta, &raw)
	scanned = raw.RegionsScanned
	if len(scanned) == 0 {
		ents, _ := os.ReadDir(r)
		for _, e := range ents {
			if e.IsDir() {
				scanned = append(scanned, e.Name())
			}
		}
		sort.Strings(scanned)
	}
	if len(scanned) > 0 {
		note(b, fmt.Sprintf("Regions scanned (%d): %s", len(scanned), strings.Join(scanned, ",")))
	}
	if len(raw.RegionsNotEnabled) > 0 {
		note(b, "Opt-in Regions not enabled (skipped; IAM is not replicated until enabled): "+strings.Join(raw.RegionsNotEnabled, ","))
	}
}

func inventory(dir, g, r string, b *strings.Builder) {
	section(b, "Inventory Snapshot")
	inst, lambda, rds := 0, 0, 0
	for _, f := range glob(r, "*/ec2/instances.json") {
		var doc struct {
			Reservations []struct {
				Instances []any `json:"Instances"`
			} `json:"Reservations"`
		}
		_ = readJSON(f, &doc)
		for _, res := range doc.Reservations {
			inst += len(res.Instances)
		}
	}
	for _, f := range glob(r, "*/lambda/functions.json") {
		var doc struct {
			Functions []any `json:"Functions"`
		}
		_ = readJSON(f, &doc)
		lambda += len(doc.Functions)
	}
	for _, f := range glob(r, "*/rds/instances.json") {
		var doc struct {
			DBInstances []any `json:"DBInstances"`
		}
		_ = readJSON(f, &doc)
		rds += len(doc.DBInstances)
	}
	var buckets struct {
		Buckets []any `json:"Buckets"`
	}
	_ = readJSON(filepath.Join(g, "s3", "list-buckets.json"), &buckets)
	var users struct {
		Users []any `json:"Users"`
	}
	_ = readJSON(filepath.Join(g, "iam", "users.json"), &users)
	var roles struct {
		Roles []any `json:"Roles"`
	}
	_ = readJSON(filepath.Join(g, "iam", "roles.json"), &roles)
	fmt.Fprintf(b, "| Resource | Count |\n|---|---:|\n")
	fmt.Fprintf(b, "| EC2 instances | %d |\n", inst)
	fmt.Fprintf(b, "| Lambda functions | %d |\n", lambda)
	fmt.Fprintf(b, "| RDS instances | %d |\n", rds)
	fmt.Fprintf(b, "| S3 buckets | %d |\n", len(buckets.Buckets))
	fmt.Fprintf(b, "| IAM users | %d |\n", len(users.Users))
	fmt.Fprintf(b, "| IAM roles | %d |\n\n", len(roles.Roles))
}

func errorsSection(dir string, b *strings.Builder) {
	p := filepath.Join(dir, "errors.log")
	raw, err := os.ReadFile(p)
	if err != nil {
		return
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	if n == 0 {
		return
	}
	section(b, "Permission / API Errors")
	note(b, fmt.Sprintf("%d log lines in `%s` — review for AccessDenied to identify blind spots.", n, p))
}

func readJSON(path string, v any) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func sj(path, key string) string {
	var m map[string]any
	if readJSON(path, &m) != nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func readCSV(path string) ([][]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var rows [][]string
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		rows = append(rows, rec)
	}
	return rows, nil
}

func glob(root, pattern string) []string {
	m, _ := filepath.Glob(filepath.Join(root, pattern))
	sort.Strings(m)
	return m
}

func regionFrom(path, svc string) string {
	// .../regions/<region>/<svc>/file.json
	dir := filepath.Dir(path)
	if filepath.Base(dir) == svc {
		return filepath.Base(filepath.Dir(dir))
	}
	return filepath.Base(filepath.Dir(filepath.Dir(path)))
}

func regionsWhere(r, rel string, pred func([]byte) bool) []string {
	var out []string
	for _, f := range glob(r, "*/"+rel) {
		raw, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		if pred(raw) {
			out = append(out, regionFrom(f, filepath.Base(filepath.Dir(f))))
		}
	}
	sort.Strings(out)
	return out
}
