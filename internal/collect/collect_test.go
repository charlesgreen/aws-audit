package collect

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/charlesgreen/aws-audit/internal/awsapi"
)

func testOpts(t *testing.T, fake *awsapi.Fake) Options {
	t.Helper()
	if fake.Identity.Account == "" {
		fake.Identity = awsapi.Identity{Account: "123456789012", ARN: "arn:aws:iam::123456789012:role/audit"}
	}
	if fake.Regions == nil {
		fake.Regions = []awsapi.RegionStatus{
			{Name: "eu-west-1", Status: "ENABLED_BY_DEFAULT"},
			{Name: "us-east-1", Status: "ENABLED_BY_DEFAULT"},
			{Name: "af-south-1", Status: "DISABLED"},
		}
	}
	return Options{
		Profile:  "audit",
		OutDir:   t.TempDir(),
		Parallel: 2,
		Client:   fake,
	}
}

func TestUnknownRegionRejectedWithoutDump(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "us-east-3"
	err := Run(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "us-east-3") {
		t.Fatalf("got %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Fatalf("must not call AWS before rejecting unknown codes: %+v", fake.Calls)
	}
}

func TestWritesMetaAndRestrictsMode(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(opts.OutDir)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("dump dir should not be group/world accessible: %o", st.Mode().Perm())
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "meta.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta map[string]any
	if err := json.Unmarshal(raw, &meta); err != nil {
		t.Fatal(err)
	}
	if meta["account_id"] != "123456789012" {
		t.Fatalf("meta: %s", raw)
	}
	if meta["partition"] != "aws" {
		t.Fatalf("partition %v", meta["partition"])
	}
	scanned, _ := meta["regions_scanned"].([]any)
	if len(scanned) != 1 || scanned[0] != "eu-west-1" {
		t.Fatalf("scanned %v", scanned)
	}
}

func TestRedactsVPNPreSharedKey(t *testing.T) {
	fake := &awsapi.Fake{
		Bodies: map[string]json.RawMessage{
			"eu-west-1|ec2|DescribeVpnConnections": json.RawMessage(`{"VpnConnections":[{"Options":{"TunnelOptions":[{"PreSharedKey":"supersecret"}]}}]}`),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "regions", "eu-west-1", "vpc", "vpn-connections.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "supersecret") {
		t.Fatalf("PSK written to disk: %s", raw)
	}
}

func TestDumpFailureWritesEmptyObjectAndErrorLog(t *testing.T) {
	fake := &awsapi.Fake{
		Errs: map[string]error{
			"|iam|ListUsers": fmtErr("AccessDenied"),
		},
	}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(opts.OutDir, "global", "iam", "users.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "{}" {
		t.Fatalf("want {} got %s", raw)
	}
	elog, _ := os.ReadFile(filepath.Join(opts.OutDir, "errors.log"))
	if !strings.Contains(string(elog), "AccessDenied") {
		t.Fatalf("errors.log: %s", elog)
	}
}

func TestSummaryMarkdownGenerated(t *testing.T) {
	fake := &awsapi.Fake{}
	opts := testOpts(t, fake)
	opts.RequestedCSV = "eu-west-1"
	if err := Run(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	md, err := os.ReadFile(filepath.Join(opts.OutDir, "summary.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(md), "Account 123456789012") {
		t.Fatalf("summary: %s", md)
	}
}

type fmtErr string

func (e fmtErr) Error() string { return string(e) }
