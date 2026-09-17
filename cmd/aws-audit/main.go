package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/charlesgreen/aws-audit/internal/awsapi"
	"github.com/charlesgreen/aws-audit/internal/collect"
	"github.com/charlesgreen/aws-audit/internal/regions"
)

// Set by GoReleaser ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	opts := collect.Options{Profile: "audit", Parallel: 4}
	listOnly := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		need := func() (string, bool) {
			if i+1 >= len(args) || args[i+1][0] == '-' {
				return "", false
			}
			i++
			return args[i], true
		}
		switch a {
		case "-h", "--help":
			fmt.Print(usage())
			return 0
		case "--version":
			fmt.Printf("aws-audit %s (commit %s, date %s)\n", Version, Commit, Date)
			return 0
		case "--list-regions":
			listOnly = true
		case "--profile":
			v, ok := need()
			if !ok {
				fmt.Fprintln(os.Stderr, "error: --profile requires a name")
				return 2
			}
			opts.Profile = v
		case "--regions":
			v, ok := need()
			if !ok {
				fmt.Fprintln(os.Stderr, "error: --regions requires a comma-separated list of Region codes (see --list-regions)")
				return 2
			}
			opts.RequestedCSV = v
		case "--out":
			v, ok := need()
			if !ok {
				fmt.Fprintln(os.Stderr, "error: --out requires a directory")
				return 2
			}
			opts.OutDir = v
		case "--parallel":
			v, ok := need()
			if !ok {
				fmt.Fprintln(os.Stderr, "error: --parallel requires a number")
				return 2
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 {
				fmt.Fprintln(os.Stderr, "error: --parallel must be a positive integer")
				return 2
			}
			opts.Parallel = n
		default:
			fmt.Fprintf(os.Stderr, "unknown arg: %s (try --help or --list-regions)\n", a)
			return 2
		}
	}
	if listOnly {
		fmt.Print(regions.FormatCatalog(""))
		return 0
	}
	if opts.RequestedCSV != "" {
		if _, err := regions.ParseRequested(opts.RequestedCSV); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n\n%s", err, regions.FormatCatalog(""))
			return 2
		}
	}
	sdk, err := awsapi.NewSDK(context.Background(), opts.Profile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load AWS config for profile %q: %v\n", opts.Profile, err)
		return 1
	}
	opts.Client = sdk
	if err := collect.Run(context.Background(), opts); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if opts.RequestedCSV != "" {
			return 2
		}
		return 1
	}
	return 0
}

func usage() string {
	return `Usage:
  aws-audit [--profile NAME] [--regions r1,r2,...] [--out DIR] [--parallel N]
  aws-audit --list-regions
  aws-audit --version
  aws-audit -h|--help

  --profile NAME       AWS CLI profile (default: audit)
  --regions r1,r2,...  Scan only these Region codes (must be valid for the
                       account partition; opt-in Regions must already be enabled)
  --out DIR            Output directory (default: ./aws-audit-<account>-<timestamp>)
  --parallel N         Concurrent regional audits (default: 4)
  --list-regions       Print valid Region codes and exit (no AWS calls)
  --version            Print version and exit
  -h, --help           Show this help and the valid Region list

Default scan: every enabled Region in the account partition (worldwide, not us-* only).

` + regions.FormatCatalog("")
}
