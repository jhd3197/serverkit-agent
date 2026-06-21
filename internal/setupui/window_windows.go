//go:build windows

package setupui

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"image/png"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	dec "github.com/lxn/walk/declarative"

	"github.com/jhd3197/serverkit-agent/internal/logger"
	"github.com/jhd3197/serverkit-agent/internal/pairdriver"
)

//go:embed serverkit.ico
var iconBytes []byte

//go:embed serverkit_header.png
var headerPNG []byte

// stage names (used as panel keys for clarity)
const (
	stageForm    = "form"
	stagePairing = "pairing"
	stageDone    = "done"
)

// runWindow shows the native pairing wizard. It blocks until the user closes
// the window (success, cancel, or X-button). Returns nil on graceful close.
//
// Walk's MainWindow event loop must run on the OS main thread; the caller
// (cmd/agent.runDesktop) is responsible for runtime.LockOSThread before us.
func runWindow(ctx context.Context, log *logger.Logger, configPath string) (retErr error) {
	runtime.LockOSThread()

	// Surface panics as a real error dialog so a misconfigured widget can
	// never produce the silent-failure mode that motivated this rewrite.
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("setup wizard panic: %v", r)
			walk.MsgBox(nil, "ServerKit Agent", retErr.Error(), walk.MsgBoxIconError)
		}
	}()

	w := &wizardUI{
		log:        log,
		configPath: configPath,
	}

	// Hook ctx cancellation into the wizard: if the parent ctx is cancelled
	// (e.g. SIGINT) we close the window from a goroutine.
	w.runCtx, w.cancel = context.WithCancel(ctx)
	defer w.cancel()

	go func() {
		<-w.runCtx.Done()
		if w.mw != nil {
			w.mw.Synchronize(func() {
				if w.mw != nil {
					w.mw.Close()
				}
			})
		}
	}()

	return w.show()
}

type wizardUI struct {
	log        *logger.Logger
	configPath string

	runCtx context.Context
	cancel context.CancelFunc

	mu          sync.Mutex
	pairCancel  context.CancelFunc

	mw *walk.MainWindow

	headerImage *walk.ImageView

	// stage 1 widgets
	urlEdit  *walk.LineEdit
	nameEdit *walk.LineEdit
	formErr  *walk.Label
	startBtn *walk.PushButton

	// stage 2 widgets
	codeLabel    *walk.Label
	passLabel    *walk.Label
	copyCodeBtn  *walk.PushButton
	copyPassBtn  *walk.PushButton
	statusLabel  *walk.Label
	pairErrLabel *walk.Label
	cancelBtn    *walk.PushButton

	// raw values backing the copy buttons (codeLabel renders a spaced version)
	rawCode string
	rawPass string

	// stage 3 widgets
	doneTitle *walk.Label
	doneSub   *walk.Label

	// stage panels
	formPanel *walk.Composite
	pairPanel *walk.Composite
	donePanel *walk.Composite
}

func (w *wizardUI) show() error {
	hostname, _ := os.Hostname()

	// Match the user's Windows theme so the wizard sits naturally on top of
	// whatever the rest of their desktop looks like. The panel's own UI is
	// light/dark adaptive; the wizard mirrors that.
	pal := detectThemePalette()

	const (
		titleSize = 14
		bodySize  = 9
		smallSize = 8
		codeSize  = 32
	)

	bgDeepBrush := pal.brushBgDeep
	bgCardBrush := pal.brushBgCard

	textWhite := pal.textHeading
	textPrimary := pal.textBody
	textLabel := pal.textLabel
	textMuted := pal.textMuted
	textHelper := pal.textHelper
	indigo := pal.indigo
	errorRed := pal.errorRed
	successGr := pal.successGr

	err := (dec.MainWindow{
		AssignTo:   &w.mw,
		Title:      "ServerKit Agent",
		MinSize:    dec.Size{Width: 460, Height: 600},
		Size:       dec.Size{Width: 460, Height: 600},
		Layout:     dec.VBox{MarginsZero: false, Margins: dec.Margins{Left: 24, Top: 24, Right: 24, Bottom: 24}, Spacing: 0},
		Background: bgDeepBrush,
		Children: []dec.Widget{
			// ── Card surface (lighter than outer bg, simulates the .agent-window block) ──
			dec.Composite{
				Layout:     dec.VBox{MarginsZero: false, Margins: dec.Margins{Left: 24, Top: 24, Right: 24, Bottom: 24}, Spacing: 0},
				Background: bgCardBrush,
				Children: []dec.Widget{
					// ── Brand header ─────────────────────────────────────────
					dec.Composite{
						Layout:     dec.HBox{MarginsZero: true, Spacing: 16},
						Background: bgCardBrush,
						Children: []dec.Widget{
							dec.ImageView{
								AssignTo: &w.headerImage,
								MinSize:  dec.Size{Width: 48, Height: 48},
								MaxSize:  dec.Size{Width: 48, Height: 48},
								Mode:     dec.ImageViewModeZoom,
								Background: bgCardBrush,
							},
							dec.Composite{
								Layout:     dec.VBox{MarginsZero: true, Spacing: 4},
								Background: bgCardBrush,
								Children: []dec.Widget{
									dec.VSpacer{},
									dec.Label{
										Text:      "Pair this server",
										Font:      dec.Font{PointSize: titleSize, Bold: true, Family: "Segoe UI"},
										TextColor: rgbHex(textWhite),
										Background: bgCardBrush,
									},
									dec.Label{
										Text:      "Connect this machine to your ServerKit panel.",
										Font:      dec.Font{PointSize: bodySize, Family: "Segoe UI"},
										TextColor: rgbHex(textMuted),
										Background: bgCardBrush,
									},
									dec.VSpacer{},
								},
							},
						},
					},

					dec.VSpacer{Size: 28},

					// ── Stage 1: connection form ─────────────────────────────
					dec.Composite{
						AssignTo:   &w.formPanel,
						Layout:     dec.VBox{MarginsZero: true, Spacing: 0},
						Background: bgCardBrush,
						Children: []dec.Widget{
							// Panel URL
							dec.Label{
								Text:       "Panel URL",
								Font:       dec.Font{Bold: true, PointSize: bodySize, Family: "Segoe UI"},
								TextColor:  rgbHex(textLabel),
								Background: bgCardBrush,
							},
							dec.VSpacer{Size: 6},
							dec.LineEdit{
								AssignTo:  &w.urlEdit,
								CueBanner: "https://panel.example.com",
								MaxLength: 500,
								MinSize:   dec.Size{Height: 28},
							},
							dec.VSpacer{Size: 6},
							dec.Label{
								Text:       "The full URL of your ServerKit control panel.",
								Font:       dec.Font{PointSize: smallSize, Family: "Segoe UI"},
								TextColor:  rgbHex(textHelper),
								Background: bgCardBrush,
							},

							dec.VSpacer{Size: 20},

							// Server name
							dec.Label{
								Text:       "Server name  (optional)",
								Font:       dec.Font{Bold: true, PointSize: bodySize, Family: "Segoe UI"},
								TextColor:  rgbHex(textLabel),
								Background: bgCardBrush,
							},
							dec.VSpacer{Size: 6},
							dec.LineEdit{
								AssignTo:  &w.nameEdit,
								Text:      hostname,
								CueBanner: "Defaults to hostname",
								MinSize:   dec.Size{Height: 28},
							},
							dec.VSpacer{Size: 6},
							dec.Label{
								Text:       "How this machine appears in your panel.",
								Font:       dec.Font{PointSize: smallSize, Family: "Segoe UI"},
								TextColor:  rgbHex(textHelper),
								Background: bgCardBrush,
							},

							dec.VSpacer{Size: 20},

							dec.Label{
								AssignTo:   &w.formErr,
								TextColor:  rgbHex(errorRed),
								Font:       dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								Background: bgCardBrush,
								Text:       "",
							},
							dec.PushButton{
								AssignTo:  &w.startBtn,
								Text:      "Connect  →",
								MinSize:   dec.Size{Height: 36},
								Font:      dec.Font{PointSize: bodySize, Bold: true, Family: "Segoe UI"},
								OnClicked: w.handleConnect,
							},
						},
					},

					// ── Stage 2: pairing code (hidden initially) ──────────────
					// Mirrors the panel's "Add Server → Pair existing agent" drawer:
					// the user reads the code here and types it into that field.
					dec.Composite{
						AssignTo:   &w.pairPanel,
						Visible:    false,
						Layout:     dec.VBox{MarginsZero: true, Spacing: 0},
						Background: bgCardBrush,
						Children: []dec.Widget{
							dec.Label{
								Text:          "On your panel, open Add Server → Pair existing agent.",
								Font:          dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								TextColor:     rgbHex(textPrimary),
								Background:    bgCardBrush,
							},
							dec.VSpacer{Size: 4},
							dec.Label{
								Text:          "Enter both values in the Pair code and Passphrase fields:",
								Font:          dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								TextColor:     rgbHex(textMuted),
								Background:    bgCardBrush,
							},
							dec.VSpacer{Size: 20},
							dec.Label{
								Text:          "Pair code",
								Font:          dec.Font{Bold: true, PointSize: smallSize, Family: "Segoe UI"},
								TextColor:     rgbHex(textLabel),
								Background:    bgCardBrush,
								TextAlignment: dec.AlignCenter,
							},
							dec.VSpacer{Size: 6},
							// Code "field" — visually echoes the panel's letter-spaced
							// input. We can't render a real bordered box, but a
							// centered Composite with the card colour at least
							// gives the code its own dedicated zone.
							dec.Composite{
								Layout:     dec.HBox{MarginsZero: true},
								Background: bgCardBrush,
								Children: []dec.Widget{
									dec.HSpacer{},
									dec.Label{
										AssignTo:      &w.codeLabel,
										Text:          "",
										Font:          dec.Font{PointSize: codeSize, Bold: true, Family: "Consolas"},
										TextColor:     rgbHex(indigo),
										Background:    bgCardBrush,
										TextAlignment: dec.AlignCenter,
									},
									dec.HSpacer{},
								},
							},
							dec.VSpacer{Size: 8},
							dec.Composite{
								Layout:     dec.HBox{MarginsZero: true},
								Background: bgCardBrush,
								Children: []dec.Widget{
									dec.HSpacer{},
									dec.PushButton{
										AssignTo:  &w.copyCodeBtn,
										Text:      "Copy",
										MinSize:   dec.Size{Width: 90, Height: 26},
										MaxSize:   dec.Size{Width: 90, Height: 26},
										Font:      dec.Font{PointSize: smallSize, Family: "Segoe UI"},
										OnClicked: w.copyCode,
									},
									dec.HSpacer{},
								},
							},
							dec.VSpacer{Size: 18},
							dec.Label{
								Text:          "Passphrase",
								Font:          dec.Font{Bold: true, PointSize: smallSize, Family: "Segoe UI"},
								TextColor:     rgbHex(textLabel),
								Background:    bgCardBrush,
								TextAlignment: dec.AlignCenter,
							},
							dec.VSpacer{Size: 6},
							dec.Composite{
								Layout:     dec.HBox{MarginsZero: true},
								Background: bgCardBrush,
								Children: []dec.Widget{
									dec.HSpacer{},
									dec.Label{
										AssignTo:      &w.passLabel,
										Text:          "",
										Font:          dec.Font{PointSize: 18, Bold: true, Family: "Consolas"},
										TextColor:     rgbHex(textPrimary),
										Background:    bgCardBrush,
										TextAlignment: dec.AlignCenter,
									},
									dec.HSpacer{},
								},
							},
							dec.VSpacer{Size: 8},
							dec.Composite{
								Layout:     dec.HBox{MarginsZero: true},
								Background: bgCardBrush,
								Children: []dec.Widget{
									dec.HSpacer{},
									dec.PushButton{
										AssignTo:  &w.copyPassBtn,
										Text:      "Copy",
										MinSize:   dec.Size{Width: 90, Height: 26},
										MaxSize:   dec.Size{Width: 90, Height: 26},
										Font:      dec.Font{PointSize: smallSize, Family: "Segoe UI"},
										OnClicked: w.copyPass,
									},
									dec.HSpacer{},
								},
							},
							dec.VSpacer{Size: 20},
							dec.Label{
								AssignTo:      &w.statusLabel,
								Text:          "Waiting for the panel to claim this server…",
								Font:          dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								TextColor:     rgbHex(textHelper),
								Background:    bgCardBrush,
								TextAlignment: dec.AlignCenter,
							},
							dec.Label{
								AssignTo:   &w.pairErrLabel,
								TextColor:  rgbHex(errorRed),
								Font:       dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								Background: bgCardBrush,
								Text:       "",
							},
							dec.VSpacer{Size: 20},
							dec.PushButton{
								AssignTo:  &w.cancelBtn,
								Text:      "Cancel",
								MinSize:   dec.Size{Height: 34},
								Font:      dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								OnClicked: w.handleCancel,
							},
						},
					},

					// ── Stage 3: success ─────────────────────────────────────
					dec.Composite{
						AssignTo:   &w.donePanel,
						Visible:    false,
						Layout:     dec.VBox{MarginsZero: true, Spacing: 10},
						Background: bgCardBrush,
						Children: []dec.Widget{
							dec.Label{
								AssignTo:   &w.doneTitle,
								Text:       "Successfully paired",
								Font:       dec.Font{PointSize: titleSize, Bold: true, Family: "Segoe UI"},
								TextColor:  rgbHex(successGr),
								Background: bgCardBrush,
							},
							dec.Label{
								AssignTo:   &w.doneSub,
								Text:       "",
								Font:       dec.Font{PointSize: bodySize, Family: "Segoe UI"},
								TextColor:  rgbHex(textPrimary),
								Background: bgCardBrush,
							},
							dec.VSpacer{Size: 8},
							dec.PushButton{
								Text:      "Close",
								MinSize:   dec.Size{Height: 36},
								Font:      dec.Font{PointSize: bodySize, Bold: true, Family: "Segoe UI"},
								OnClicked: func() { w.mw.Close() },
							},
						},
					},

					dec.VSpacer{},

					// Subtle in-card footer mirrors the panel's brand strip.
					dec.Composite{
						Layout:     dec.HBox{MarginsZero: true},
						Background: bgCardBrush,
						Children: []dec.Widget{
							dec.HSpacer{},
							dec.Label{
								Text:       "ServerKit  •  Pairing wizard",
								Font:       dec.Font{PointSize: smallSize, Family: "Segoe UI"},
								TextColor:  rgbHex(textHelper),
								Background: bgCardBrush,
							},
							dec.HSpacer{},
						},
					},
				},
			},
		},
	}).Create()
	if err != nil {
		return fmt.Errorf("create window: %w", err)
	}

	if icon, err := loadAppIcon(); err == nil && icon != nil {
		_ = w.mw.SetIcon(icon)
	}
	if bmp, err := loadHeaderBitmap(); err == nil && bmp != nil && w.headerImage != nil {
		_ = w.headerImage.SetImage(bmp)
	}

	// Title-bar chrome stays system-default; we're light-themed everywhere
	// for now to avoid the dark-card / white-input contrast clash.
	w.mw.Show()
	// Windows' anti-focus-stealing rule will leave the window invisible behind
	// the desktop when the agent is launched from the Start menu shortcut.
	// scheduleForceForeground retries the AttachThreadInput-based activation
	// recipe several times across the first ~1.5s of window life so we win
	// regardless of when walk's message pump actually starts servicing.
	scheduleForceForeground(w.mw)
	w.mw.Run()

	w.mu.Lock()
	if w.pairCancel != nil {
		w.pairCancel()
	}
	w.mu.Unlock()

	return nil
}

// handleConnect is fired by the "Connect" button. Validates inputs, kicks off
// pairing in a goroutine, and transitions to the pairing stage on success.
func (w *wizardUI) handleConnect() {
	url := w.urlEdit.Text()
	name := w.nameEdit.Text()

	if url == "" {
		w.formErr.SetText("Panel URL is required.")
		return
	}
	pass, err := pairdriver.GeneratePassphrase()
	if err != nil {
		w.formErr.SetText("Could not generate a passphrase: " + err.Error())
		return
	}
	w.rawPass = pass
	w.formErr.SetText("")
	w.startBtn.SetEnabled(false)
	w.startBtn.SetText("Connecting…")

	pairCtx, cancel := context.WithCancel(w.runCtx)
	w.mu.Lock()
	w.pairCancel = cancel
	w.mu.Unlock()

	cb := pairdriver.Callbacks{
		OnEnrolled: func(code, formatted string) {
			w.mw.Synchronize(func() {
				w.rawCode = code
				w.codeLabel.SetText(displayCode(code, formatted))
				w.passLabel.SetText(pass)
				w.showStage(stagePairing)
			})
		},
		OnClaimed: func(serverName string) {
			w.mw.Synchronize(func() {
				if serverName == "" {
					serverName = "this server"
				}
				w.doneSub.SetText(fmt.Sprintf("This machine is now connected to ServerKit as %q.\n\nThe agent service has been started in the background. You can close this window.", serverName))
				w.showStage(stageDone)
			})
			startServiceIfInstalled()
		},
		OnError: func(err error) {
			w.mw.Synchronize(func() {
				msg := errorPretty(err)
				if w.pairPanel.Visible() {
					w.pairErrLabel.SetText(msg)
					w.cancelBtn.SetText("Try again")
				} else {
					w.formErr.SetText(msg)
					w.startBtn.SetEnabled(true)
					w.startBtn.SetText("Connect")
				}
			})
		},
	}

	go pairdriver.Run(pairCtx, w.log, w.configPath, url, pass, name, cb)
}

// handleCancel rolls back to the form stage and cancels any in-flight pairing.
func (w *wizardUI) handleCancel() {
	w.mu.Lock()
	if w.pairCancel != nil {
		w.pairCancel()
		w.pairCancel = nil
	}
	w.mu.Unlock()

	w.formErr.SetText("")
	w.pairErrLabel.SetText("")
	w.codeLabel.SetText("")
	w.passLabel.SetText("")
	w.copyCodeBtn.SetText("Copy")
	w.copyPassBtn.SetText("Copy")
	w.rawCode = ""
	w.rawPass = ""
	w.cancelBtn.SetText("Cancel")
	w.startBtn.SetEnabled(true)
	w.startBtn.SetText("Connect")
	w.showStage(stageForm)
}

// copyCode / copyPass place the raw value on the clipboard and flash the
// button label so the user has visual confirmation that the click landed.
func (w *wizardUI) copyCode() { w.copyToClipboard(w.rawCode, w.copyCodeBtn) }
func (w *wizardUI) copyPass() { w.copyToClipboard(w.rawPass, w.copyPassBtn) }

func (w *wizardUI) copyToClipboard(value string, btn *walk.PushButton) {
	if value == "" || btn == nil {
		return
	}
	if cb := walk.Clipboard(); cb != nil {
		_ = cb.SetText(value)
	}
	btn.SetText("Copied!")
	time.AfterFunc(1500*time.Millisecond, func() {
		if w.mw == nil {
			return
		}
		w.mw.Synchronize(func() {
			if btn != nil {
				btn.SetText("Copy")
			}
		})
	})
}

func (w *wizardUI) showStage(stage string) {
	w.formPanel.SetVisible(stage == stageForm)
	w.pairPanel.SetVisible(stage == stagePairing)
	w.donePanel.SetVisible(stage == stageDone)
}

// errorPretty turns errors from runPairing into a user-friendly one-liner.
func errorPretty(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) {
		return "Cancelled."
	}
	return err.Error()
}

// displayCode renders the pair code with letter-spacing, mirroring the
// panel's "Add Server" input field which uses CSS letter-spacing: 0.5em on
// the same code. Walk Labels don't support letter-spacing as a property, so
// we fake it by inserting two-space gaps between glyphs of the unformatted
// code. Result for code "AB12CD" looks like "A  B  1  2  C  D".
func displayCode(code, formatted string) string {
	raw := code
	if raw == "" {
		raw = formatted
	}
	clean := strings.ReplaceAll(raw, "-", "")
	clean = strings.ReplaceAll(clean, " ", "")
	if clean == "" {
		return ""
	}
	var b strings.Builder
	for i, r := range clean {
		if i > 0 {
			b.WriteString("  ")
		}
		b.WriteRune(r)
	}
	return b.String()
}

func rgbHex(rgb uint32) walk.Color {
	return walk.RGB(byte(rgb>>16), byte(rgb>>8), byte(rgb))
}

// loadAppIcon writes the embedded .ico to a temp file (walk doesn't load icons
// from raw bytes) and returns it. The temp file lingers until process exit;
// Windows handles cleanup of %TEMP%.
var (
	iconOnce sync.Once
	iconRef  *walk.Icon
)

func loadAppIcon() (*walk.Icon, error) {
	iconOnce.Do(func() {
		f, err := os.CreateTemp("", "serverkit-*.ico")
		if err != nil {
			return
		}
		_, _ = f.Write(iconBytes)
		_ = f.Close()
		ic, err := walk.NewIconFromFile(f.Name())
		if err != nil {
			return
		}
		iconRef = ic
	})
	if iconRef == nil {
		return nil, fmt.Errorf("icon not loaded")
	}
	return iconRef, nil
}

// loadHeaderBitmap decodes the embedded brand PNG into a walk Bitmap suitable
// for an ImageView. Must be called after the walk runtime is up (i.e. after
// MainWindow.Create), otherwise the underlying GDI calls return errors.
var (
	headerOnce sync.Once
	headerBmp  *walk.Bitmap
)

func loadHeaderBitmap() (*walk.Bitmap, error) {
	headerOnce.Do(func() {
		img, err := png.Decode(bytes.NewReader(headerPNG))
		if err != nil {
			return
		}
		bmp, err := walk.NewBitmapFromImageForDPI(img, 96)
		if err != nil {
			return
		}
		headerBmp = bmp
	})
	if headerBmp == nil {
		return nil, fmt.Errorf("header bitmap not loaded")
	}
	return headerBmp, nil
}
