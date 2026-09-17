package awsapi

import (
	"context"
	"encoding/json"
)

// Identity is sts GetCallerIdentity.
type Identity struct {
	Account string
	ARN     string
}

// RegionStatus is one row from account ListRegions.
type RegionStatus struct {
	Name   string
	Status string // ENABLED, ENABLED_BY_DEFAULT, DISABLED, ...
}

// Dump is one List/Describe/Get call whose JSON is written to the audit tree.
type Dump struct {
	Region    string
	Service   string
	Operation string
	Input     map[string]string
}

// Client is the injectable AWS surface. Production uses SDK v2; tests use Fake.
type Client interface {
	CallerIdentity(ctx context.Context) (Identity, error)
	ListAccountRegions(ctx context.Context, homeRegion string) ([]RegionStatus, error)
	EC2DescribeEnabledRegions(ctx context.Context, homeRegion string) ([]string, error)
	Dump(ctx context.Context, req Dump) (json.RawMessage, error)
}
