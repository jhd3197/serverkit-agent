package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/permissions"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func permissionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "permissions",
		Short: "Show or change this agent's permission level",
		Long: `The permission level (monitor, protect or full) is stored only in the
local config and can never be changed from the panel. Changing it requires
root on this machine and a typed confirmation.`,
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "show",
		Short: "Show the active permission level and what it allows",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load(cfgFile)
			if err != nil {
				return err
			}
			level, err := cfg.PermissionLevel()
			if err != nil {
				return err
			}
			printLevelTable(os.Stdout, level)
			return nil
		},
	})
	var yes bool
	set := &cobra.Command{
		Use:   "set <monitor|protect|full>",
		Short: "Change the permission level (root; restarts the service)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPermissionsSet(args[0], yes, os.Stdin, os.Stdout)
		},
	}
	set.Flags().BoolVar(&yes, "yes", false, "skip the typed confirmation (for scripted use on this machine)")
	cmd.AddCommand(set)
	return cmd
}

func printLevelTable(w io.Writer, active permissions.Level) {
	fmt.Fprintf(w, "Permission level: %s\n  %s\n\nLevels:\n", active, active.Describe())
	for _, l := range []permissions.Level{permissions.Monitor, permissions.Protect, permissions.Full} {
		mark := " "
		if l == active {
			mark = "*"
		}
		fmt.Fprintf(w, " %s %-8s %s\n", mark, l, l.Describe())
	}
	fmt.Fprintln(w, "\nChange with: serverkit-agent permissions set <monitor|protect|full>")
}

// banner is printed after install/register so the operator knows exactly
// what the panel can do on this machine.
func printLevelBanner(w io.Writer, l permissions.Level) {
	fmt.Fprintf(w, "\n==================================================\n")
	fmt.Fprintf(w, " Permission level: %s\n", strings.ToUpper(string(l)))
	fmt.Fprintf(w, " %s\n", l.Describe())
	fmt.Fprintf(w, " Change it later (as root, on this machine only):\n")
	fmt.Fprintf(w, "   serverkit-agent permissions set <monitor|protect|full>\n")
	fmt.Fprintf(w, "==================================================\n")
}

func isRoot() bool {
	if runtime.GOOS == "windows" {
		return true // elevation is enforced by the service control manager
	}
	return os.Geteuid() == 0
}

// confirmLevel requires the operator to type the level name.
func confirmLevel(in io.Reader, out io.Writer, l permissions.Level) error {
	fmt.Fprintf(out, "Type %q to confirm: ", l)
	line, _ := bufio.NewReader(in).ReadString('\n')
	if strings.TrimSpace(line) != string(l) {
		return fmt.Errorf("confirmation did not match; permission level unchanged")
	}
	return nil
}

func runPermissionsSet(arg string, yes bool, in io.Reader, out io.Writer) error {
	target, err := permissions.Parse(arg)
	if err != nil {
		return err
	}
	if !isRoot() {
		return fmt.Errorf("changing the permission level must be run as root on this machine (try sudo)")
	}
	path := cfgFile
	if path == "" {
		path = config.DefaultConfigPath()
	}
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	cur, err := cfg.PermissionLevel()
	if err != nil {
		return err
	}
	if cur == target {
		fmt.Fprintf(out, "Permission level is already %s.\n", cur)
		return nil
	}
	fmt.Fprintf(out, "Current level: %s\nNew level:     %s\n  %s\n\n", cur, target, target.Describe())
	if !yes {
		if err := confirmLevel(in, out, target); err != nil {
			return err
		}
	}
	cfg.Permissions.Level = string(target)
	if err := cfg.Save(path); err != nil {
		return err
	}
	fmt.Fprintf(out, "Permission level set to %s.\n", target)
	if err := restartService(); err != nil {
		fmt.Fprintf(out, "Could not restart the service automatically (%v).\nRestart it to apply the change.\n", err)
		return nil
	}
	fmt.Fprintln(out, "Service restarted.")
	return nil
}

func restartService() error {
	switch runtime.GOOS {
	case "linux":
		return exec.Command("systemctl", "restart", "serverkit-agent").Run()
	case "windows":
		return exec.Command("powershell", "-NoProfile", "-Command", "Restart-Service", "ServerKitAgent").Run()
	}
	return fmt.Errorf("unsupported platform")
}

func stdinIsTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
}

// promptLevel shows the interactive menu.
func promptLevel(in io.Reader, out io.Writer) (permissions.Level, error) {
	fmt.Fprintln(out, "\nChoose what this agent may do on this server:")
	fmt.Fprintln(out, "  1) monitor  - "+permissions.Monitor.Describe())
	fmt.Fprintln(out, "  2) protect  - "+permissions.Protect.Describe())
	fmt.Fprintln(out, "  3) full     - "+permissions.Full.Describe())
	fmt.Fprint(out, "Selection [1-3 or name]: ")
	line, _ := bufio.NewReader(in).ReadString('\n')
	switch s := strings.TrimSpace(line); s {
	case "1":
		return permissions.Monitor, nil
	case "2":
		return permissions.Protect, nil
	case "3":
		return permissions.Full, nil
	default:
		return permissions.Parse(s)
	}
}

// resolveRegisterLevel picks the level for `register`: explicit flag, else the
// level already in an existing config, else the menu on a TTY, else full with
// a loud warning (legacy command compatibility).
func resolveRegisterLevel(flag string, existing *config.Config, tty bool, in io.Reader, out io.Writer) (permissions.Level, error) {
	var cur permissions.Level
	haveCfg := existing != nil && existing.Agent.ID != ""
	if haveCfg {
		var err error
		if cur, err = existing.PermissionLevel(); err != nil {
			return "", err
		}
	}
	if flag != "" {
		l, err := permissions.Parse(flag)
		if err != nil {
			return "", err
		}
		if haveCfg && l != cur {
			return "", fmt.Errorf("this agent is already registered at level %s; use 'serverkit-agent permissions set %s' (as root) to change it", cur, l)
		}
		return l, nil
	}
	if haveCfg {
		return cur, nil
	}
	if tty {
		return promptLevel(in, out)
	}
	fmt.Fprintln(out, "WARNING: no --level given and no terminal; defaulting to FULL control.")
	fmt.Fprintln(out, "         Pass --level monitor|protect|full to choose explicitly.")
	return permissions.Full, nil
}
