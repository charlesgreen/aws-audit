# AWS Configuration Audit

Read-only CLI that snapshots AWS account configuration and writes a findings report. Use it for monthly security reviews and as evidence toward ISO 27001 and SOC 2 technical controls.

Implemented in Go with AWS SDK v2. Sibling tool: [gcp-audit](https://github.com/charlesgreen/gcp-audit).

## Install

From a [GitHub Release](https://github.com/charlesgreen/aws-audit/releases) (Linux amd64; replace the version):

```bash
curl -L https://github.com/charlesgreen/aws-audit/releases/download/v0.1.0/aws-audit_0.1.0_Linux_x86_64.tar.gz | tar xz
sudo mv aws-audit aws-audit-summarize /usr/local/bin/
```

From source:

```bash
go install github.com/charlesgreen/aws-audit/cmd/aws-audit@latest
go install github.com/charlesgreen/aws-audit/cmd/aws-audit-summarize@latest
```

A `v*` tag on `main` runs [GoReleaser](https://goreleaser.com) and publishes archives, checksums, and SBOMs.

## Prerequisites

- Go 1.24+ (from source)
- An AWS profile with read-only access to the target account. Default profile name: `audit`.

```bash
aws sts get-caller-identity --profile audit
```

The AWS CLI is only needed to confirm the profile. The collector talks to AWS through the SDK.

## Quick start

```bash
go run ./cmd/aws-audit --list-regions
go run ./cmd/aws-audit --profile audit
```

After `make build`, the same flags work on `./bin/aws-audit`. After `go install` or a release archive, use `aws-audit` on your `PATH`.

## Usage

Default run: every enabled Region in the account partition (worldwide, not `us-*` only), parallelism 4.

```bash
aws-audit --profile audit
```

Common overrides:

```bash
aws-audit --profile audit --regions eu-west-1,ap-northeast-1,sa-east-1
aws-audit --out /tmp/audit-2026-01-01 --parallel 8
```

Print every valid Region code (no AWS credentials):

```bash
aws-audit --list-regions
```

Re-run the summary against an existing dump:

```bash
aws-audit-summarize ./aws-audit-123456789012-20260101-120000 > /tmp/summary.md
```

`aws-audit --help` lists flags and the Region catalog.

## Audit output

Each run writes a directory of live account metadata. Treat it as confidential: it can include account IDs, IAM users and credential-report rows, Route 53 records, account contact emails, security-group rules, secret and parameter names, and public IPs. Do not commit it, paste it into tickets, or share it outside the people who own the audited account.

This repo gitignores `/aws-audit-*/` at the repo root (the default output path). If you pass `--out`, keep that directory outside the working tree.

VPN pre-shared keys, Auto Scaling `UserData`, CloudFront origin header values, and customer-gateway configuration XML are replaced with `[REDACTED]` before write. The collector does not call `GetSecretValue`, `ssm:GetParameter`, or `s3:GetObject`.

## Regions

By default the collector audits **every Region the account can use**, not only `us-*`.

Region discovery follows [AWS Account Management](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-regions.html) and the [AWS Regions table](https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html):

1. `account:ListRegions` — official list of every Region plus opt-in status. Scans `ENABLED_BY_DEFAULT` and `ENABLED`.
2. If that API is denied, `ec2:DescribeRegions` with `--all-regions` filtered to `opt-in-not-required` and `opted-in`.
3. If both fail, the 17 default (always-on) commercial Regions from the docs — Asia Pacific, Canada, Europe, South America, and US — not `us-east-1` alone.

Opt-in Regions that are still `DISABLED` are skipped (IAM is not replicated there until you enable them) and listed in `meta.json` as `regions_not_enabled`.

`--regions` restricts the scan to a comma-separated subset. Codes must be valid AWS Region IDs for the account's partition, and opt-in Regions must already be enabled. Unknown codes fail immediately and print the valid list. `--help` and `--list-regions` print the same catalog (code + long name), grouped as default vs opt-in vs GovCloud vs China.

**Default Regions** (enabled at account creation, cannot be disabled): `ap-northeast-1` Asia Pacific (Tokyo), `ap-northeast-2` Asia Pacific (Seoul), `ap-northeast-3` Asia Pacific (Osaka), `ap-south-1` Asia Pacific (Mumbai), `ap-southeast-1` Asia Pacific (Singapore), `ap-southeast-2` Asia Pacific (Sydney), `ca-central-1` Canada (Central), `eu-central-1` Europe (Frankfurt), `eu-north-1` Europe (Stockholm), `eu-west-1` Europe (Ireland), `eu-west-2` Europe (London), `eu-west-3` Europe (Paris), `sa-east-1` South America (São Paulo), `us-east-1` US East (N. Virginia), `us-east-2` US East (Ohio), `us-west-1` US West (N. California), `us-west-2` US West (Oregon).

**Opt-in Regions** (must be enabled before they can be queried): `af-south-1` Africa (Cape Town), `ap-east-1` Asia Pacific (Hong Kong), `ap-east-2` Asia Pacific (Taipei), `ap-south-2` Asia Pacific (Hyderabad), `ap-southeast-3` Asia Pacific (Jakarta), `ap-southeast-4` Asia Pacific (Melbourne), `ap-southeast-5` Asia Pacific (Malaysia), `ap-southeast-6` Asia Pacific (New Zealand), `ap-southeast-7` Asia Pacific (Thailand), `ca-west-1` Canada West (Calgary), `eu-central-2` Europe (Zurich), `eu-south-1` Europe (Milan), `eu-south-2` Europe (Spain), `il-central-1` Israel (Tel Aviv), `me-central-1` Middle East (UAE), `me-south-1` Middle East (Bahrain), `mx-central-1` Mexico (Central).

GovCloud (`us-gov-east-1` AWS GovCloud (US-East), `us-gov-west-1` AWS GovCloud (US-West)) and China (`cn-north-1` China (Beijing), `cn-northwest-1` China (Ningxia)) are separate partitions. A commercial account cannot list or access them.

## Output layout

```text
aws-audit-<account>-<UTC-timestamp>/
  meta.json                       # account id, principal, start time
  errors.log                      # every failed API call (esp. AccessDenied)
  summary.md                      # human-readable findings report
  global/
    iam/                          # users, roles, policies, credential report, per-user details
    organizations/                # org structure, SCPs
    account/                      # contacts, regions
    s3/                           # account public access block + per-bucket config
    route53/                      # zones, records, query logging
    cloudfront/                   # distributions, OACs, functions
    waf/                          # CLOUDFRONT-scope WAFv2 ACLs/IP sets
    support/                      # Trusted Advisor (requires Business/Enterprise support)
  regions/
    <region>/
      ec2/ vpc/ elb/ autoscaling/
      lambda/ ecs/ eks/ ecr/
      rds/ dynamodb/ elasticache/ redshift/ opensearch/
      efs/ fsx/ backup/
      kms/ secretsmanager/ ssm/
      security/                   # CloudTrail, Config, GuardDuty, Security Hub, Inspector, Macie, Access Analyzer, Detective
      logs/ sns/ sqs/ events/ apigw/ acm/ waf/ tags/
```

## What the summary checks

- **IAM:** root MFA, root access keys, users without MFA, access keys >90d, weak password policy, inline user policies.
- **Account services:** missing/weak CloudTrail (multi-region, log file validation, KMS, actively logging); GuardDuty / AWS Config / Security Hub / Access Analyzer disabled per region.
- **Network:** security groups with `0.0.0.0/0` ingress; default VPCs in use; VPCs without flow logs.
- **S3:** account-level public access block; per-bucket public status, public access block, encryption, versioning, logging, static website.
- **Compute/data encryption:** EBS encryption-by-default off; unencrypted EBS volumes; publicly accessible RDS; unencrypted RDS; RDS 0-day backup retention; EC2 not enforcing IMDSv2; public-IP EC2 instances.
- **KMS:** customer-managed keys without rotation.
- **ACM:** certs expiring in <30 days.
- **Logging:** CloudWatch log groups with no retention.
- **Cost/governance:** unattached EBS volumes; unassociated Elastic IPs; untagged resources.

## Permissions

The collector is read-only: `Describe*`, `List*`, `Get*` plus `sts:GetCallerIdentity` and `iam:GenerateCredentialReport` (generates the in-account report only; no other mutation).

Any API the profile cannot access lands in `errors.log` and the corresponding output file becomes `{}`. The summary section "Permission / API Errors" surfaces the count so you know where blind spots may exist.

## Performance

Regions run in parallel (default 4 concurrent). A full audit of a typical multi-region account takes 5–15 minutes. Tune with `--parallel`.

Each run writes to a new timestamped directory; nothing is overwritten. Diff two output trees to compare months.

## Build and test

```bash
make check    # gofmt, go vet, go test (no AWS credentials)
make build    # ./bin/aws-audit and ./bin/aws-audit-summarize
```

CI runs the same gate on every push. Tests use a fake AWS client; they never call live APIs.

Optional repo-root wrappers (`aws-audit.sh`, `aws-audit-summarize.sh`) exec `./bin/*` if present, otherwise `go run ./cmd/...`. Releases and `PATH` installs use the Go binaries, not the wrappers.

## Caveats

- `support:DescribeTrustedAdvisorChecks` requires AWS Business or Enterprise Support — expect a permission failure on basic-tier accounts.
- `account:GetAlternateContact` requires the management account or appropriate delegation.
- WAFv2 CLOUDFRONT-scope queries run from the partition home Region (`us-east-1` commercially); the collector handles that automatically.
- Account-level S3 public access block requires `s3:GetAccountPublicAccessBlock`.
- If `iam:GetCredentialReport` fails, credential-report findings are skipped.

## License

MIT. See [LICENSE](LICENSE).
