package regions

import (
	"strings"
	"testing"
)

func TestLookupKnownCommercial(t *testing.T) {
	r, ok := Lookup("eu-west-1")
	if !ok {
		t.Fatal("eu-west-1 should be in the catalog")
	}
	if r.Name != "Europe (Ireland)" {
		t.Fatalf("name: %q", r.Name)
	}
	if r.Class != ClassDefault || r.Partition != "aws" {
		t.Fatalf("class/partition: %s %s", r.Class, r.Partition)
	}
}

func TestLookupUnknown(t *testing.T) {
	if _, ok := Lookup("us-east-3"); ok {
		t.Fatal("us-east-3 is not a real Region")
	}
}

func TestParseRequestedRejectsUnknown(t *testing.T) {
	_, err := ParseRequested("us-east-1,us-east-3")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "us-east-3") {
		t.Fatalf("error should name the unknown code: %v", err)
	}
}

func TestParseRequestedNormalizesCaseAndSpace(t *testing.T) {
	got, err := ParseRequested(" EU-WEST-1 , ap-northeast-1 ")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "eu-west-1" || got[1] != "ap-northeast-1" {
		t.Fatalf("got %v", got)
	}
}

func TestFilterForAccountWrongPartition(t *testing.T) {
	_, err := FilterForAccount([]string{"us-gov-west-1"}, "aws", []string{"us-east-1"}, false)
	if err == nil {
		t.Fatal("expected wrong-partition error")
	}
	if !strings.Contains(err.Error(), "aws-us-gov") {
		t.Fatalf("error should mention partition: %v", err)
	}
}

func TestFilterForAccountNotEnabled(t *testing.T) {
	_, err := FilterForAccount([]string{"af-south-1"}, "aws", []string{"us-east-1", "eu-west-1"}, false)
	if err == nil {
		t.Fatal("expected not-enabled error")
	}
}

func TestFilterForAccountFallbackAllowsOptIn(t *testing.T) {
	got, err := FilterForAccount([]string{"af-south-1"}, "aws", []string{"us-east-1"}, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "af-south-1" {
		t.Fatalf("got %v", got)
	}
}

func TestDefaultsAreWorldwide(t *testing.T) {
	d := DefaultCodes("aws")
	want := []string{"ap-northeast-1", "eu-west-1", "sa-east-1", "us-east-1"}
	set := map[string]bool{}
	for _, c := range d {
		set[c] = true
	}
	for _, c := range want {
		if !set[c] {
			t.Fatalf("default list missing %s (not us-* only)", c)
		}
	}
	if set["af-south-1"] {
		t.Fatal("opt-in Cape Town must not be in the always-on default list")
	}
}

func TestCatalogContainsAllPartitions(t *testing.T) {
	if _, ok := Lookup("us-gov-east-1"); !ok {
		t.Fatal("missing GovCloud")
	}
	if _, ok := Lookup("cn-north-1"); !ok {
		t.Fatal("missing China")
	}
	if _, ok := Lookup("mx-central-1"); !ok {
		t.Fatal("missing Mexico")
	}
}

func TestFormatCatalogMentionsDocs(t *testing.T) {
	s := FormatCatalog("")
	for _, needle := range []string{
		"eu-west-1",
		"Africa (Cape Town)",
		"GovCloud",
		"docs.aws.amazon.com/global-infrastructure",
	} {
		if !strings.Contains(s, needle) {
			t.Fatalf("catalog missing %q", needle)
		}
	}
}

func TestHomeRegion(t *testing.T) {
	if HomeRegion("aws") != "us-east-1" {
		t.Fatal(HomeRegion("aws"))
	}
	if HomeRegion("aws-us-gov") != "us-gov-west-1" {
		t.Fatal(HomeRegion("aws-us-gov"))
	}
	if HomeRegion("aws-cn") != "cn-northwest-1" {
		t.Fatal(HomeRegion("aws-cn"))
	}
}

func TestPartitionFromARN(t *testing.T) {
	if p := PartitionFromARN("arn:aws:iam::123:user/x"); p != "aws" {
		t.Fatal(p)
	}
	if p := PartitionFromARN("arn:aws-us-gov:iam::123:user/x"); p != "aws-us-gov" {
		t.Fatal(p)
	}
}
