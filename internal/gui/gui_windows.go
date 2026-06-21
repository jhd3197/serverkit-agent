//go:build windows

package gui

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// PowerShell snippet: capture the primary screen with System.Drawing,
// optionally downscale, encode to JPEG/PNG, base64-emit to stdout. We
// pass scale and quality as args; format is selected by name.
//
// Why PowerShell instead of a Go-native call: System.Drawing ships in every
// Windows install since the dawn of time, and shelling out keeps the agent
// free of GDI cgo wrappers. Slow, but at 1–2 fps it's invisible.
const psCaptureScript = `
param(
  [double]$Scale = 0.75,
  [int]$Quality = 70,
  [string]$Format = "jpeg"
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms

$bounds = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$srcW = $bounds.Width
$srcH = $bounds.Height

$bmp = New-Object System.Drawing.Bitmap $srcW, $srcH
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($bounds.X, $bounds.Y, 0, 0, $bounds.Size)

if ($Scale -lt 1.0 -and $Scale -gt 0) {
  $dstW = [int]([Math]::Round($srcW * $Scale))
  $dstH = [int]([Math]::Round($srcH * $Scale))
  $resized = New-Object System.Drawing.Bitmap $dstW, $dstH
  $rg = [System.Drawing.Graphics]::FromImage($resized)
  $rg.InterpolationMode = "HighQualityBicubic"
  $rg.DrawImage($bmp, 0, 0, $dstW, $dstH)
  $rg.Dispose()
  $bmp.Dispose()
  $bmp = $resized
}

$ms = New-Object System.IO.MemoryStream
if ($Format -eq "png") {
  $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
} else {
  $codecs = [System.Drawing.Imaging.ImageCodecInfo]::GetImageEncoders()
  $jpegCodec = $codecs | Where-Object { $_.MimeType -eq "image/jpeg" } | Select-Object -First 1
  $params = New-Object System.Drawing.Imaging.EncoderParameters 1
  $params.Param[0] = New-Object System.Drawing.Imaging.EncoderParameter ([System.Drawing.Imaging.Encoder]::Quality), [long]$Quality
  $bmp.Save($ms, $jpegCodec, $params)
}

$bytes = $ms.ToArray()
$ms.Dispose()
$bmp.Dispose()

# Emit a single line: WIDTH HEIGHT BASE64
[Console]::Out.Write("$($bmp.Width) $($bmp.Height) ")
[Console]::Out.WriteLine([Convert]::ToBase64String($bytes))
`

func detectCapabilities() (Capabilities, error) {
	res, err := runPowerShell(context.Background(), `
$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds 2>$null
if ($b) { Write-Output ("{0}x{1}" -f $b.Width, $b.Height) }
`, 5*time.Second)
	if err != nil || strings.TrimSpace(res) == "" {
		// Most common cause: agent running as a Windows service in
		// session 0 with no logged-in user. The bitmap will exist but
		// we won't capture anything visible.
		return Capabilities{
			Capability:        "none",
			SyntheticFallback: true,
			Reason:            "no active user session",
		}, nil
	}
	return Capabilities{
		Capability:        "windows-gdi",
		Resolution:        strings.TrimSpace(res),
		MaxFPS:            5,
		SyntheticFallback: false,
	}, nil
}

func captureFrame(ctx context.Context, p ScreenshotParams) (*Frame, error) {
	args := []string{
		"-Scale", strconv.FormatFloat(p.Scale, 'f', 3, 64),
		"-Quality", strconv.Itoa(p.Quality),
		"-Format", p.Format,
	}
	out, err := runPowerShellWithArgs(ctx, psCaptureScript, args, 15*time.Second)
	if err != nil {
		return nil, err
	}
	// stdout is "WIDTH HEIGHT BASE64\n"
	line := strings.TrimSpace(out)
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed capture output: %q", truncate(line, 120))
	}
	w, err1 := strconv.Atoi(parts[0])
	h, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return nil, errors.New("malformed dimensions")
	}
	// Sanity-check the base64 payload but don't decode it; the panel does that.
	if _, err := base64.StdEncoding.DecodeString(parts[2][:min(64, len(parts[2]))]); err != nil {
		return nil, fmt.Errorf("invalid base64 prefix: %w", err)
	}
	return &Frame{
		ImageBase64: parts[2],
		Format:      p.Format,
		Width:       w,
		Height:      h,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func runPowerShell(ctx context.Context, script string, timeout time.Duration) (string, error) {
	return runPowerShellWithArgs(ctx, script, nil, timeout)
}

func runPowerShellWithArgs(ctx context.Context, script string, args []string, timeout time.Duration) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	bin := "powershell"
	if p, err := exec.LookPath("pwsh"); err == nil {
		bin = p
	}

	all := []string{
		"-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-Command", script,
	}
	all = append(all, args...)

	cmd := exec.CommandContext(cctx, bin, all...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
