package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func runCA(args []string) {
	if len(args) == 0 || args[0] != "export" {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy ca export [--out <path>]")
		os.Exit(1)
	}

	fs := flag.NewFlagSet("ca export", flag.ExitOnError)
	outPath := fs.String("out", "", "Destination path to write CA certificate PEM")
	_ = fs.Parse(args[1:])

	vouchDir := defaultVouchDir()
	caCertPath := filepath.Join(vouchDir, "ca.crt")
	data, err := os.ReadFile(caCertPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading CA cert: %v\n", err)
		os.Exit(1)
	}

	if *outPath != "" {
		if err := os.WriteFile(*outPath, data, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing CA cert to %s: %v\n", *outPath, err)
			os.Exit(1)
		}
		fmt.Printf("✓ Exported Root CA to %s\n", *outPath)
	} else {
		fmt.Print(string(data))
	}
}
