package regions

import (
	"fmt"
	"sort"
	"strings"
)

// Class is whether a Region is always-on or opt-in.
type Class string

const (
	ClassDefault Class = "default"
	ClassOptIn   Class = "opt-in"
)

// Info is one official AWS Region.
// https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html
type Info struct {
	Code      string
	Name      string
	Class     Class
	Partition string
}

var catalog = []Info{
	{"af-south-1", "Africa (Cape Town)", ClassOptIn, "aws"},
	{"ap-east-1", "Asia Pacific (Hong Kong)", ClassOptIn, "aws"},
	{"ap-east-2", "Asia Pacific (Taipei)", ClassOptIn, "aws"},
	{"ap-northeast-1", "Asia Pacific (Tokyo)", ClassDefault, "aws"},
	{"ap-northeast-2", "Asia Pacific (Seoul)", ClassDefault, "aws"},
	{"ap-northeast-3", "Asia Pacific (Osaka)", ClassDefault, "aws"},
	{"ap-south-1", "Asia Pacific (Mumbai)", ClassDefault, "aws"},
	{"ap-south-2", "Asia Pacific (Hyderabad)", ClassOptIn, "aws"},
	{"ap-southeast-1", "Asia Pacific (Singapore)", ClassDefault, "aws"},
	{"ap-southeast-2", "Asia Pacific (Sydney)", ClassDefault, "aws"},
	{"ap-southeast-3", "Asia Pacific (Jakarta)", ClassOptIn, "aws"},
	{"ap-southeast-4", "Asia Pacific (Melbourne)", ClassOptIn, "aws"},
	{"ap-southeast-5", "Asia Pacific (Malaysia)", ClassOptIn, "aws"},
	{"ap-southeast-6", "Asia Pacific (New Zealand)", ClassOptIn, "aws"},
	{"ap-southeast-7", "Asia Pacific (Thailand)", ClassOptIn, "aws"},
	{"ca-central-1", "Canada (Central)", ClassDefault, "aws"},
	{"ca-west-1", "Canada West (Calgary)", ClassOptIn, "aws"},
	{"eu-central-1", "Europe (Frankfurt)", ClassDefault, "aws"},
	{"eu-central-2", "Europe (Zurich)", ClassOptIn, "aws"},
	{"eu-north-1", "Europe (Stockholm)", ClassDefault, "aws"},
	{"eu-south-1", "Europe (Milan)", ClassOptIn, "aws"},
	{"eu-south-2", "Europe (Spain)", ClassOptIn, "aws"},
	{"eu-west-1", "Europe (Ireland)", ClassDefault, "aws"},
	{"eu-west-2", "Europe (London)", ClassDefault, "aws"},
	{"eu-west-3", "Europe (Paris)", ClassDefault, "aws"},
	{"il-central-1", "Israel (Tel Aviv)", ClassOptIn, "aws"},
	{"me-central-1", "Middle East (UAE)", ClassOptIn, "aws"},
	{"me-south-1", "Middle East (Bahrain)", ClassOptIn, "aws"},
	{"mx-central-1", "Mexico (Central)", ClassOptIn, "aws"},
	{"sa-east-1", "South America (São Paulo)", ClassDefault, "aws"},
	{"us-east-1", "US East (N. Virginia)", ClassDefault, "aws"},
	{"us-east-2", "US East (Ohio)", ClassDefault, "aws"},
	{"us-west-1", "US West (N. California)", ClassDefault, "aws"},
	{"us-west-2", "US West (Oregon)", ClassDefault, "aws"},
	{"us-gov-east-1", "AWS GovCloud (US-East)", ClassDefault, "aws-us-gov"},
	{"us-gov-west-1", "AWS GovCloud (US-West)", ClassDefault, "aws-us-gov"},
	{"cn-north-1", "China (Beijing)", ClassDefault, "aws-cn"},
	{"cn-northwest-1", "China (Ningxia)", ClassDefault, "aws-cn"},
}

var byCode = func() map[string]Info {
	m := make(map[string]Info, len(catalog))
	for _, r := range catalog {
		m[r.Code] = r
	}
	return m
}()

// Lookup returns catalog data for a Region code.
func Lookup(code string) (Info, bool) {
	r, ok := byCode[strings.ToLower(strings.TrimSpace(code))]
	return r, ok
}

// DefaultCodes are always-on Regions for a partition (cannot be disabled).
func DefaultCodes(partition string) []string {
	var out []string
	for _, r := range catalog {
		if r.Partition == partition && r.Class == ClassDefault {
			out = append(out, r.Code)
		}
	}
	return out
}

// CodesForPartition returns every catalog code in a partition.
func CodesForPartition(partition string) []string {
	var out []string
	for _, r := range catalog {
		if r.Partition == partition {
			out = append(out, r.Code)
		}
	}
	return out
}

// HomeRegion is the partition's Account Management / Organizations endpoint Region.
func HomeRegion(partition string) string {
	switch partition {
	case "aws-us-gov":
		return "us-gov-west-1"
	case "aws-cn":
		return "cn-northwest-1"
	default:
		return "us-east-1"
	}
}

// PartitionFromARN reads the second field of an ARN.
func PartitionFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) > 1 && strings.HasPrefix(parts[0], "arn") {
		switch parts[1] {
		case "aws-us-gov", "aws-cn":
			return parts[1]
		}
	}
	return "aws"
}

// ParseRequested splits a comma-separated --regions value and rejects unknown codes.
func ParseRequested(csv string) ([]string, error) {
	var out []string
	var unknown []string
	seen := map[string]bool{}
	for _, p := range strings.Split(csv, ",") {
		code := strings.ToLower(strings.TrimSpace(p))
		if code == "" {
			continue
		}
		if _, ok := Lookup(code); !ok {
			unknown = append(unknown, code)
			continue
		}
		if !seen[code] {
			seen[code] = true
			out = append(out, code)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown Region code(s): %s", strings.Join(unknown, ","))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--regions did not contain any Region codes")
	}
	return out, nil
}

// FilterForAccount checks partition and enabled status.
// If discoveryFallback is true (Region APIs failed), opt-in codes in the catalog are allowed.
func FilterForAccount(requested []string, partition string, enabled []string, discoveryFallback bool) ([]string, error) {
	en := map[string]bool{}
	for _, c := range enabled {
		en[c] = true
	}
	var out []string
	var wrong, notEnabled []string
	for _, code := range requested {
		info, ok := Lookup(code)
		if !ok {
			return nil, fmt.Errorf("unknown Region code(s): %s", code)
		}
		if info.Partition != partition {
			wrong = append(wrong, fmt.Sprintf("%s  %s  (partition %s)", code, info.Name, info.Partition))
			continue
		}
		if !discoveryFallback && !en[code] {
			notEnabled = append(notEnabled, fmt.Sprintf("%s  %s  (%s, not enabled on this account)", code, info.Name, info.Class))
			continue
		}
		out = append(out, code)
	}
	if len(wrong) > 0 || len(notEnabled) > 0 {
		var b strings.Builder
		b.WriteString("error: --regions contains Region codes that cannot be scanned")
		if len(wrong) > 0 {
			b.WriteString("\n\nWrong partition for this account (" + partition + "):\n")
			for _, w := range wrong {
				b.WriteString("  " + w + "\n")
			}
			b.WriteString("GovCloud and China cannot be queried from a commercial account (and vice versa).\n")
		}
		if len(notEnabled) > 0 {
			b.WriteString("\nValid AWS Region(s) but not enabled on this account:\n")
			for _, w := range notEnabled {
				b.WriteString("  " + w + "\n")
			}
		}
		return nil, fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
	}
	sort.Strings(out)
	return out, nil
}

// FormatCatalog prints the human-readable valid-Region list.
func FormatCatalog(onlyPartition string) string {
	var b strings.Builder
	b.WriteString("Valid AWS Region codes\n")
	b.WriteString("https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html\n")
	b.WriteString("Pass a comma-separated subset with --regions (example: --regions eu-west-1,ap-northeast-1).\n\n")
	writeGroup := func(part, title string, class Class) {
		if onlyPartition != "" && onlyPartition != part {
			return
		}
		b.WriteString(title + "\n")
		for _, r := range catalog {
			if r.Partition == part && r.Class == class {
				fmt.Fprintf(&b, "  %-16s  %s\n", r.Code, r.Name)
			}
		}
		b.WriteByte('\n')
	}
	writeGroup("aws", "Commercial (aws) — default (always on):", ClassDefault)
	writeGroup("aws", "Commercial (aws) — opt-in (must be enabled on the account before they can be scanned):", ClassOptIn)
	writeGroup("aws-us-gov", "GovCloud (aws-us-gov) — separate partition; not reachable from a commercial account:", ClassDefault)
	writeGroup("aws-cn", "China (aws-cn) — separate partition; not reachable from a commercial account:", ClassDefault)
	return b.String()
}
