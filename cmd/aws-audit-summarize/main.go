package main

import (
	"fmt"
	"os"

	"github.com/charlesgreen/aws-audit/internal/summarize"
)

// Set by GoReleaser ldflags.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("aws-audit-summarize %s (commit %s, date %s)\n", Version, Commit, Date)
		os.Exit(0)
	}
	if len(os.Args) != 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		fmt.Fprintf(os.Stderr, "Usage: %s <audit-output-dir>\n", os.Args[0])
		os.Exit(2)
	}
	md, err := summarize.Report(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(md)
}
