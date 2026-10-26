package agent

import "testing"

// TestAptListUsesDpkgQuery guards issue #1: apt-get has no `list`
// subcommand, so listing installed packages must go through dpkg-query.
func TestAptListUsesDpkgQuery(t *testing.T) {
	pm := &packageManager{
		bin:     "apt-get",
		list:    []string{"-W", "-f=${Package}\t${Version}\n"},
		listBin: "dpkg-query",
	}
	bin, args := pm.listCommand()
	if bin != "dpkg-query" {
		t.Fatalf("list bin = %q, want dpkg-query", bin)
	}
	if len(args) == 0 || args[0] != "-W" {
		t.Fatalf("list args = %v, want -W first", args)
	}

	dnf := &packageManager{bin: "dnf", list: []string{"list", "installed"}}
	if bin, _ := dnf.listCommand(); bin != "dnf" {
		t.Fatalf("dnf list bin = %q, want dnf", bin)
	}
}
