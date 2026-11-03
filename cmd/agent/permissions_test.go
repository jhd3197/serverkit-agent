package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/permissions"
)

func registered(level string) *config.Config {
	c := config.Default()
	c.Agent.ID = "abc"
	c.Permissions.Level = level
	return c
}

func TestResolveRegisterLevel(t *testing.T) {
	var out bytes.Buffer
	cases := []struct {
		name     string
		flag     string
		existing *config.Config
		tty      bool
		input    string
		want     permissions.Level
		wantErr  string
	}{
		{"flag wins on fresh box", "monitor", nil, false, "", permissions.Monitor, ""},
		{"bad flag fails", "root", nil, false, "", "", "unknown permission level"},
		{"non-tty without flag is full", "", nil, false, "", permissions.Full, ""},
		{"tty menu by number", "", nil, true, "2\n", permissions.Protect, ""},
		{"tty menu by name", "", nil, true, "monitor\n", permissions.Monitor, ""},
		{"tty menu garbage", "", nil, true, "x\n", "", "unknown permission level"},
		{"existing level kept", "", registered("protect"), false, "", permissions.Protect, ""},
		{"legacy existing is full", "", registered(""), true, "", permissions.Full, ""},
		{"downgrade via register refused", "monitor", registered("full"), false, "", "", "permissions set monitor"},
		{"same level ok", "protect", registered("protect"), false, "", permissions.Protect, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveRegisterLevel(c.flag, c.existing, c.tty, strings.NewReader(c.input), &out)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q", got, err, c.want)
			}
		})
	}
	if !strings.Contains(out.String(), "WARNING") {
		t.Error("non-interactive default to full must warn loudly")
	}
}

func TestConfirmLevel(t *testing.T) {
	var out bytes.Buffer
	if err := confirmLevel(strings.NewReader("monitor\n"), &out, permissions.Monitor); err != nil {
		t.Fatal(err)
	}
	if err := confirmLevel(strings.NewReader("yes\n"), &out, permissions.Monitor); err == nil {
		t.Fatal("wrong confirmation accepted")
	}
	if err := confirmLevel(strings.NewReader(""), &out, permissions.Monitor); err == nil {
		t.Fatal("EOF accepted as confirmation")
	}
}
