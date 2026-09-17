package awsapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// Fake is an in-memory Client for tests. No network.
type Fake struct {
	mu       sync.Mutex
	Identity Identity
	Regions  []RegionStatus
	EC2Regs  []string
	Bodies   map[string]json.RawMessage
	Errs     map[string]error
	Calls    []Dump
}

func key(d Dump) string {
	return d.Region + "|" + d.Service + "|" + d.Operation
}

func (f *Fake) CallerIdentity(context.Context) (Identity, error) {
	if f.Identity.Account == "" {
		return Identity{}, fmt.Errorf("not authenticated")
	}
	return f.Identity, nil
}

func (f *Fake) ListAccountRegions(context.Context, string) ([]RegionStatus, error) {
	if f.Regions == nil {
		return nil, fmt.Errorf("account list-regions unavailable")
	}
	return f.Regions, nil
}

func (f *Fake) EC2DescribeEnabledRegions(context.Context, string) ([]string, error) {
	if f.EC2Regs == nil {
		return nil, fmt.Errorf("ec2 describe-regions unavailable")
	}
	return f.EC2Regs, nil
}

func (f *Fake) Dump(_ context.Context, req Dump) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Calls = append(f.Calls, req)
	k := key(req)
	if err, ok := f.Errs[k]; ok {
		return nil, err
	}
	if b, ok := f.Bodies[k]; ok {
		return b, nil
	}
	return json.RawMessage(`{}`), nil
}
