package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old

	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestDetectShell(t *testing.T) {
	tests := []struct {
		flag     string
		envShell string
		expected string
	}{
		{"bash", "", "sh"},
		{"zsh", "", "sh"},
		{"sh", "", "sh"},
		{"fish", "", "fish"},
		{"powershell", "", "powershell"},
		{"pwsh", "", "powershell"},
		{"ps1", "", "powershell"},
		{"auto", "/bin/zsh", "sh"},
		{"auto", "/usr/bin/fish", "fish"},
		{"auto", "/usr/local/bin/pwsh", "powershell"},
	}

	for _, tt := range tests {
		t.Run(tt.flag+"_"+tt.envShell, func(t *testing.T) {
			if tt.envShell != "" {
				_ = os.Setenv("SHELL", tt.envShell)
			}
			res := detectShell(tt.flag)
			if res != tt.expected {
				t.Errorf("detectShell(%q) [SHELL=%q] = %q, expected %q", tt.flag, tt.envShell, res, tt.expected)
			}
		})
	}
}

func TestPrintExportEnv(t *testing.T) {
	envVars := map[string]string{
		"HTTP_PROXY": "http://session:sec@127.0.0.1:8080",
		"NO_PROXY":   "",
	}

	shOut := captureStdout(func() {
		printExportEnv("sh", envVars)
	})
	if !strings.Contains(shOut, `export HTTP_PROXY="http://session:sec@127.0.0.1:8080"`) {
		t.Fatalf("expected export statement in sh output, got:\n%s", shOut)
	}

	fishOut := captureStdout(func() {
		printExportEnv("fish", envVars)
	})
	if !strings.Contains(fishOut, `set -gx HTTP_PROXY "http://session:sec@127.0.0.1:8080";`) {
		t.Fatalf("expected set -gx statement in fish output, got:\n%s", fishOut)
	}

	psOut := captureStdout(func() {
		printExportEnv("powershell", envVars)
	})
	if !strings.Contains(psOut, `$env:HTTP_PROXY = "http://session:sec@127.0.0.1:8080"`) {
		t.Fatalf("expected $env: statement in powershell output, got:\n%s", psOut)
	}
}

func TestPrintUnsetEnv(t *testing.T) {
	dummyTokens := map[string]string{
		"OPENAI_API_KEY": "VP_OPENAI_API_KEY_DUMMY_123",
	}

	shOut := captureStdout(func() {
		printUnsetEnv("sh", dummyTokens)
	})
	if !strings.Contains(shOut, "unset HTTP_PROXY") || !strings.Contains(shOut, "OPENAI_API_KEY") {
		t.Fatalf("expected unset statements in sh output, got:\n%s", shOut)
	}

	fishOut := captureStdout(func() {
		printUnsetEnv("fish", dummyTokens)
	})
	if !strings.Contains(fishOut, "set -e HTTP_PROXY;") {
		t.Fatalf("expected set -e in fish output, got:\n%s", fishOut)
	}

	psOut := captureStdout(func() {
		printUnsetEnv("powershell", dummyTokens)
	})
	if !strings.Contains(psOut, "Remove-Item env:HTTP_PROXY") {
		t.Fatalf("expected Remove-Item in powershell output, got:\n%s", psOut)
	}
}
