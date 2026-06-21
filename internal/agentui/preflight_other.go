//go:build !windows

package agentui

func detectWebView2() string         { return "" }
func preflightWebView2() error       { return nil }
