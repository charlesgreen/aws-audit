package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitignoreDoesNotIgnoreSummarizeCmd(t *testing.T) {
	root := findMod(t)
	data, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "aws-audit-*/" {
			t.Fatal("unanchored aws-audit-*/ ignores cmd/aws-audit-summarize; use /aws-audit-*/")
		}
	}
	if _, err := os.Stat(filepath.Join(root, "cmd/aws-audit-summarize/main.go")); err != nil {
		t.Fatalf("cmd/aws-audit-summarize/main.go missing: %v", err)
	}
}

func TestCheckWorkflowDoesNotTriggerOnTags(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(findMod(t), ".github/workflows/check.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(data), "\r\n", "\n")
	if strings.Contains(s, "on:\n  push:\n  pull_request:") {
		t.Fatal("check.yml on.push has no branch filter; tag pushes run check and Release together")
	}
	if !strings.Contains(s, "branches:") {
		t.Fatal("check.yml must restrict push to branches so tags only run Release")
	}
}
