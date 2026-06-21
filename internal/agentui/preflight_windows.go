//go:build windows

package agentui

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

// WebView2 evergreen runtime registers itself under this UUID. We probe both
// the 32-bit and 64-bit hives plus per-user, mirroring Microsoft's own
// detection guidance. If pv is non-empty we treat the runtime as installed.
//
// https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/distribution#detect-if-a-webview2-runtime-is-already-installed
const webview2GUID = `{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`

// detectWebView2 returns the installed runtime version, or empty string if
// not installed. Errors at the registry layer are folded into "not present"
// — the calling code only needs a yes/no with a version when found.
func detectWebView2() string {
	candidates := []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
		{registry.CURRENT_USER, `Software\Microsoft\EdgeUpdate\Clients\` + webview2GUID},
	}
	for _, c := range candidates {
		k, err := registry.OpenKey(c.root, c.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue("pv")
		k.Close()
		if err == nil && v != "" {
			return v
		}
	}
	return ""
}

// preflightWebView2 returns nil when the runtime is present, or an error
// pointing the user at the download URL. We surface this *before* trying
// to construct the webview, because go-webview2's NewWithOptions can
// silently produce a non-nil but non-functional handle in certain
// failure modes — leaving the user with a blank window and no error.
func preflightWebView2() error {
	v := detectWebView2()
	if v == "" {
		return fmt.Errorf(
			"WebView2 runtime not installed. " +
				"Install the Evergreen Bootstrapper from " +
				"https://developer.microsoft.com/microsoft-edge/webview2/ and try again",
		)
	}
	return nil
}
