package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestListRegionsNoAWS(t *testing.T) {
	exe := build(t)
	out, err := exec.Command(exe, "--list-regions").CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, "eu-west-1") || !strings.Contains(s, "Africa (Cape Town)") {
		t.Fatalf("catalog:\n%s", s)
	}
}

func TestUnknownRegionExit2(t *testing.T) {
	exe := build(t)
	cmd := exec.Command(exe, "--regions", "us-east-3")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected failure")
	}
	if cmd.ProcessState.ExitCode() != 2 {
		t.Fatalf("exit %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
	if !strings.Contains(string(out), "us-east-3") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestHelpExit0(t *testing.T) {
	exe := build(t)
	out, err := exec.Command(exe, "--help").CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "--list-regions") {
		t.Fatalf("%s", out)
	}
}

func build(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	exe := filepath.Join(dir, "aws-audit")
	cmd := exec.Command("go", "build", "-o", exe, ".")
	cmd.Dir = filepath.Join(findMod(t), "cmd", "aws-audit")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return exe
}

func findMod(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
