package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestVPNPreSharedKey(t *testing.T) {
	in := []byte(`{"VpnConnections":[{"VpnConnectionId":"vpn-1","Options":{"TunnelOptions":[{"PreSharedKey":"supersecret"}]}}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "supersecret") {
		t.Fatalf("PSK leaked: %s", out)
	}
	if !strings.Contains(string(out), redacted) {
		t.Fatalf("expected redaction marker: %s", out)
	}
}

func TestLaunchConfigUserData(t *testing.T) {
	in := []byte(`{"LaunchConfigurations":[{"LaunchConfigurationName":"web","UserData":"#!/bin/bash\nexport DB_PASSWORD=hunter2"}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "hunter2") {
		t.Fatal("UserData leaked")
	}
}

func TestCloudFrontOriginHeader(t *testing.T) {
	in := []byte(`{"DistributionList":{"Items":[{"Origins":{"Items":[{"CustomHeaders":{"Items":[{"HeaderName":"X-Origin","HeaderValue":"shared-secret"}]}}]}}]}}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "shared-secret") {
		t.Fatal("origin header leaked")
	}
}

func TestCustomerGatewayXML(t *testing.T) {
	in := []byte(`{"VpnConnections":[{"CustomerGatewayConfiguration":"<vpn><psk>abc123</psk></vpn>"}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "abc123") {
		t.Fatal("gateway XML leaked")
	}
}

func TestLeavesOtherFields(t *testing.T) {
	in := []byte(`{"Buckets":[{"Name":"logs"}]}`)
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal(out, &v); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidJSONPassthrough(t *testing.T) {
	in := []byte("not-json")
	out, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "not-json" {
		t.Fatalf("got %q", out)
	}
}
