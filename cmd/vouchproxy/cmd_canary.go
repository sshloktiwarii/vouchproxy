package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/canary"
)

func runCanary(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy canary <mint|verify> [arguments...]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	switch subCmd {
	case "mint":
		fs := flag.NewFlagSet("canary mint", flag.ExitOnError)
		promptID := fs.String("prompt", "", "Prompt identifier")
		keyName := fs.String("key", "", "Key name to associate with canary")
		ttlStr := fs.String("ttl", "1h", "Time-to-live duration (e.g. 10m, 1h, -120s)")
		_ = fs.Parse(subArgs)

		if *promptID == "" || *keyName == "" {
			fmt.Fprintln(os.Stderr, "Error: --prompt and --key are required")
			os.Exit(1)
		}

		ttl, err := time.ParseDuration(*ttlStr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing --ttl: %v\n", err)
			os.Exit(1)
		}

		token, err := canary.Mint(*promptID, *keyName, ttl)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error minting canary token: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(token)

	case "verify":
		fs := flag.NewFlagSet("canary verify", flag.ExitOnError)
		token := fs.String("token", "", "Canary token to verify")
		_ = fs.Parse(subArgs)

		if *token == "" {
			fmt.Fprintln(os.Stderr, "Error: --token is required")
			os.Exit(1)
		}

		tok, err := canary.Verify(*token)
		if err != nil {
			fmt.Printf("Verification failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "Error: canary token verification failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Canary token valid:\n  Prompt ID: %s\n  Key Name:  %s\n  Expires:   %s\n",
			tok.PromptID, tok.KeyName, tok.ExpiresAt.Format(time.RFC3339))

	default:
		fmt.Fprintf(os.Stderr, "Unknown canary subcommand: %s\n", subCmd)
		os.Exit(1)
	}
}
