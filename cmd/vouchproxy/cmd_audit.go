package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/sshloktiwarii/vouchproxy/internal/audit"
)

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	logPath := fs.String("log", filepath.Join(defaultVouchDir(), "audit.jsonl"), "Path to audit JSONL file")
	hostFilter := fs.String("host", "", "Filter by destination host")
	actionFilter := fs.String("action", "", "Filter by action (INJECT_SECRET, BLOCK_LEAK, SCRUB_PII)")
	limit := fs.Int("limit", 20, "Number of events to display")
	tailMode := fs.Bool("tail", false, "Read latest events in reverse chronological order")
	jsonOutput := fs.Bool("json", false, "Output in JSON format")
	_ = fs.Parse(args)

	var events []audit.AuditEvent
	var err error

	if *tailMode || *limit > 0 {
		events, err = audit.Tail(*logPath, audit.TailOptions{
			Limit:  *limit,
			Host:   *hostFilter,
			Action: *actionFilter,
		})
	} else {
		events, err = audit.ReadAll(*logPath)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading audit log: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(events)
		return
	}

	if len(events) == 0 {
		fmt.Println("No audit events recorded.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "TIMESTAMP\tACTION\tSTATUS\tMETHOD\tHOST\tPATH\tINJECTED KEY\tSCRUBS\tLATENCY")
	for _, ev := range events {
		ts := ev.Timestamp.Format("15:04:05")
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\t%s\t%s\t%d\t%.1fms\n",
			ts, ev.Action, ev.HTTPStatus, ev.HTTPMethod, ev.Host, ev.PathSanitized, ev.InjectedKeyName, ev.ScrubCount, ev.LatencyMs)
	}
	_ = w.Flush()
}
