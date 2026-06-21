//go:build windows

package setupui

import (
	"github.com/lxn/walk"
	dec "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows/registry"
)

// palette holds the colour tokens used by the wizard. We carry separate
// light/dark instances and pick at startup based on the user's Windows
// theme, mirroring the panel's own light/dark behaviour.
type palette struct {
	dark bool

	bgDeep      uint32 // outer window background
	bgCard      uint32 // card surface
	textHeading uint32 // section titles
	textBody    uint32 // descriptive body
	textLabel   uint32 // form labels
	textMuted   uint32 // subtitles
	textHelper  uint32 // helper text under inputs / footer
	indigo      uint32 // brand accent (button text + pair code)
	errorRed    uint32
	successGr   uint32

	// Brushes derived from the colours above. Cached to avoid recomputing
	// the same SolidColorBrush thousands of times during widget construction.
	brushBgDeep dec.Brush
	brushBgCard dec.Brush
}

func newPalette(dark bool) palette {
	if dark {
		p := palette{
			dark:        true,
			bgDeep:      0x09090B,
			bgCard:      0x121214,
			textHeading: 0xFFFFFF,
			textBody:    0xEDEDED,
			textLabel:   0xE4E4E7,
			textMuted:   0xA1A1AA,
			textHelper:  0x71717A,
			indigo:      0x818CF8, // slightly lifted for contrast on dark bg
			errorRed:    0xF87171,
			successGr:   0x34D399,
		}
		p.brushBgDeep = dec.SolidColorBrush{Color: rgbHex(p.bgDeep)}
		p.brushBgCard = dec.SolidColorBrush{Color: rgbHex(p.bgCard)}
		return p
	}
	p := palette{
		dark:        false,
		bgDeep:      0xF1F5F9, // slate-100, gentler than pure white
		bgCard:      0xFFFFFF,
		textHeading: 0x111827,
		textBody:    0x1F2937,
		textLabel:   0x374151,
		textMuted:   0x6B7280,
		textHelper:  0x9CA3AF,
		indigo:      0x4F46E5,
		errorRed:    0xDC2626,
		successGr:   0x059669,
	}
	p.brushBgDeep = dec.SolidColorBrush{Color: rgbHex(p.bgDeep)}
	p.brushBgCard = dec.SolidColorBrush{Color: rgbHex(p.bgCard)}
	return p
}

// detectThemePalette currently always returns the light palette regardless
// of the user's Windows theme preference. Walk's native LineEdit and
// PushButton controls don't reliably respect dark mode (the white-input-on-
// dark-card contrast looks broken), so until the wizard is ported to Wails
// we keep a single, consistent light palette. The registry-reading path is
// preserved below in case we want to flip this back when the controls
// behave.
func detectThemePalette() palette {
	return newPalette(false)
}

// systemPrefersDark is the would-be feature toggle we'd hand detectThemePalette
// once we actually have themable inputs (i.e. after the Wails port).
func systemPrefersDark() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER,
		`Software\Microsoft\Windows\CurrentVersion\Themes\Personalize`,
		registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue("AppsUseLightTheme")
	if err != nil {
		return false
	}
	return v == 0
}

func (p palette) Color(c uint32) walk.Color { return rgbHex(c) }
