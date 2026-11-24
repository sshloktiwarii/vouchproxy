package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sshloktiwarii/vouchproxy/internal/crypto"
	"github.com/sshloktiwarii/vouchproxy/internal/vault"
)

func runSecret(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret <set|list|delete> [args...]")
		os.Exit(1)
	}

	subCmd := args[0]
	subArgs := args[1:]

	vouchDir := defaultVouchDir()
	vaultPath := filepath.Join(vouchDir, "vault.enc")

	switch subCmd {
	case "set":
		if len(subArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret set <KEY_NAME>")
			os.Exit(1)
		}
		keyName := strings.ToUpper(strings.TrimSpace(subArgs[0]))

		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		secretVal, err := readPasswordMasked(fmt.Sprintf("Enter secret value for %s: ", keyName))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		defer crypto.ZeroBytes(secretVal)

		if err := v.Set(keyName, secretVal); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting secret: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Secret %q stored encrypted in vault. Bound dummy token: %s\n",
			keyName, vault.GenerateDummyToken(keyName))

	case "list":
		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		items := v.List()
		if len(items) == 0 {
			fmt.Println("No secrets stored in vault.")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "KEY NAME\tDUMMY TOKEN\tCREATED AT")
		for _, item := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\n", item.KeyName, item.DummyToken, time.Unix(item.CreatedAt, 0).Format("2006-01-02 15:04:05"))
		}
		_ = w.Flush()

	case "delete", "rm":
		if len(subArgs) == 0 {
			fmt.Fprintln(os.Stderr, "Usage: vouchproxy secret delete <KEY_NAME>")
			os.Exit(1)
		}
		keyName := strings.ToUpper(strings.TrimSpace(subArgs[0]))

		v, err := unlockVault(vaultPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening vault: %v\n", err)
			os.Exit(1)
		}
		defer v.Close()

		if err := v.Delete(keyName); err != nil {
			fmt.Fprintf(os.Stderr, "Error deleting secret: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✓ Secret %q deleted from vault.\n", keyName)

	default:
		fmt.Fprintf(os.Stderr, "Unknown secret command: %s\n", subCmd)
		os.Exit(1)
	}
}
