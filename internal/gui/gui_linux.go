//go:build linux

package gui

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func detectCapabilities() (Capabilities, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if hasOnPath("grim") {
			return Capabilities{
				Capability:        "linux-wayland",
				MaxFPS:            3,
				SyntheticFallback: false,
			}, nil
		}
	}
	if os.Getenv("DISPLAY") != "" {
		for _, bin := range []string{"scrot", "import", "gnome-screenshot"} {
			if hasOnPath(bin) {
				return Capabilities{
					Capability:        "linux-x11",
					MaxFPS:            3,
					SyntheticFallback: false,
				}, nil
			}
		}
		return Capabilities{
			Capability:        "none",
			SyntheticFallback: true,
			Reason:            "X11 detected but no scrot/import/gnome-screenshot installed",
		}, nil
	}
	return Capabilities{
		Capability:        "none",
		SyntheticFallback: true,
		Reason:            "no display server (headless)",
	}, nil
}

func captureFrame(ctx context.Context, p ScreenshotParams) (*Frame, error) {
	raw, capturedFormat, err := captureRawPNG(ctx)
	if err != nil {
		return nil, err
	}

	// Decode → optionally downscale → re-encode to requested format.
	// We pay the decode cost so we can guarantee Scale + Quality work
	// regardless of which capture tool we used.
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		// Some tools occasionally emit non-PNG; if the panel asked for
		// the same format we already have, pass it through verbatim.
		if capturedFormat == p.Format {
			return &Frame{
				ImageBase64: base64.StdEncoding.EncodeToString(raw),
				Format:      capturedFormat,
				CapturedAt:  time.Now().UTC().Format(time.RFC3339),
			}, nil
		}
		return nil, fmt.Errorf("decode capture: %w", err)
	}

	if p.Scale > 0 && p.Scale < 1.0 {
		src = nearestScale(src, p.Scale)
	}

	var buf bytes.Buffer
	switch p.Format {
	case "png":
		if err := png.Encode(&buf, src); err != nil {
			return nil, fmt.Errorf("png encode: %w", err)
		}
	default:
		if err := jpeg.Encode(&buf, src, &jpeg.Options{Quality: p.Quality}); err != nil {
			return nil, fmt.Errorf("jpeg encode: %w", err)
		}
	}

	b := src.Bounds()
	return &Frame{
		ImageBase64: base64.StdEncoding.EncodeToString(buf.Bytes()),
		Format:      p.Format,
		Width:       b.Dx(),
		Height:      b.Dy(),
		CapturedAt:  time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// captureRawPNG returns raw bytes from whichever capture tool is available.
// Format is always "png" today, but returned explicitly to leave room for
// JPEG-native captures in the future.
func captureRawPNG(ctx context.Context) ([]byte, string, error) {
	switch {
	case os.Getenv("WAYLAND_DISPLAY") != "" && hasOnPath("grim"):
		out, err := run(ctx, "grim", "-")
		return out, "png", err

	case hasOnPath("scrot"):
		// scrot can write PNG to a file; it can't write to stdout in
		// every version, so we take the file route via /dev/stdout
		// where supported.
		out, err := run(ctx, "scrot", "-o", "/dev/stdout")
		if err != nil {
			// Older scrot — fall back to a temp file.
			return scrotViaTemp(ctx)
		}
		return out, "png", nil

	case hasOnPath("import"):
		out, err := run(ctx, "import", "-window", "root", "png:-")
		return out, "png", err
	}
	return nil, "", errors.New("no screenshot tool on PATH (install scrot, grim, or imagemagick)")
}

func scrotViaTemp(ctx context.Context) ([]byte, string, error) {
	f, err := os.CreateTemp("", "sk-scrot-*.png")
	if err != nil {
		return nil, "", err
	}
	path := f.Name()
	f.Close()
	defer os.Remove(path)

	if _, err := run(ctx, "scrot", "-o", path); err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	return data, "png", nil
}

func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s: %w (%s)", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

func hasOnPath(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// nearestScale is a stdlib-only scaler. Quality is fine for streaming
// previews at 50–75%; we don't need bilinear/bicubic here.
func nearestScale(src image.Image, scale float64) image.Image {
	b := src.Bounds()
	dstW := int(float64(b.Dx()) * scale)
	dstH := int(float64(b.Dy()) * scale)
	if dstW < 1 {
		dstW = 1
	}
	if dstH < 1 {
		dstH = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	for y := 0; y < dstH; y++ {
		sy := b.Min.Y + int(float64(y)/scale)
		for x := 0; x < dstW; x++ {
			sx := b.Min.X + int(float64(x)/scale)
			dst.Set(x, y, src.At(sx, sy))
		}
	}
	return dst
}

// Avoid an unused-import warning when strconv isn't used in a build variant.
var _ = strconv.Itoa
