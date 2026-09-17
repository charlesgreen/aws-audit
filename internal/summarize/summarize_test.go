package summarize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMissingDumpDir(t *testing.T) {
	_, err := Report("/no/such/dump")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFindingsFromFixture(t *testing.T) {
	md, err := Report(filepath.Join("testdata", "sample"))
	if err != nil {
		t.Fatal(err)
	}
	needles := []string{
		"Account 123456789012",
		"HIGH: Root account MFA disabled",
		"HIGH: No CloudTrail trails found",
		"HIGH: Security groups expose ports to the public internet",
		"HIGH: Publicly accessible RDS instances",
		"HIGH: Account-level S3 Public Access Block not fully enabled",
		"MEDIUM: GuardDuty disabled in regions",
		"Partition: aws (home Region us-east-1)",
		"Regions scanned (1): eu-west-1",
		"Permission / API Errors",
	}
	for _, n := range needles {
		if !strings.Contains(md, n) {
			t.Errorf("missing %q\n--- report ---\n%s", n, md)
		}
	}
	if strings.Contains(md, "supersecret") {
		t.Error("fixture must not contain live secrets")
	}
}

func TestEmptyErrorsOmitsSection(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, filepath.Join("testdata", "sample"), dir)
	if err := os.WriteFile(filepath.Join(dir, "errors.log"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	md, err := Report(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(md, "Permission / API Errors") {
		t.Fatal("empty errors.log should not produce the errors section")
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}
