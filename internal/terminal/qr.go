package terminal

import (
	"fmt"
	"io"
	"os"

	"github.com/skip2/go-qrcode"
)

const (
	AnsiReset       = "\033[0m"
	AnsiWhiteBgDark = "\033[47;30m" // White background, Black foreground

	CharFullBlock  = '█'
	CharUpperBlock = '▀'
	CharLowerBlock = '▄'
	CharSpace      = ' '
)

// RenderQRCodeHalfBlock renders content as a compact half-block Unicode QR code
// suitable for 80x24 standard terminals. It writes to the specified io.Writer.
func RenderQRCodeHalfBlock(w io.Writer, content string) error {
	qr, err := qrcode.New(content, qrcode.Low)
	if err != nil {
		return fmt.Errorf("failed to generate QR code: %w", err)
	}

	bm := qr.Bitmap()
	height := len(bm)
	if height == 0 {
		return fmt.Errorf("empty QR bitmap")
	}
	width := len(bm[0])

	useColor := os.Getenv("NO_COLOR") == ""

	// Quiet zone margin (modules)
	margin := 1
	totalWidth := width + margin*2
	totalHeight := height + margin*2

	// Helper to get module (true = dark/black, false = light/white)
	getModule := func(y, x int) bool {
		origY := y - margin
		origX := x - margin
		if origY < 0 || origY >= height || origX < 0 || origX >= width {
			return false // Quiet zone is white/light
		}
		return bm[origY][origX]
	}

	// Render 2 rows per line using half blocks
	for y := 0; y < totalHeight; y += 2 {
		if useColor {
			fmt.Fprint(w, AnsiWhiteBgDark)
		}
		for x := 0; x < totalWidth; x++ {
			top := getModule(y, x)
			bottom := false
			if y+1 < totalHeight {
				bottom = getModule(y+1, x)
			}

			// In AnsiWhiteBgDark:
			// Background is White (light)
			// Foreground is Black (dark)
			switch {
			case top && bottom:
				fmt.Fprint(w, string(CharFullBlock))
			case top && !bottom:
				fmt.Fprint(w, string(CharUpperBlock))
			case !top && bottom:
				fmt.Fprint(w, string(CharLowerBlock))
			default:
				fmt.Fprint(w, string(CharSpace))
			}
		}
		if useColor {
			fmt.Fprint(w, AnsiReset)
		}
		fmt.Fprintln(w)
	}

	return nil
}

// PrintPairingPrompt renders the terminal QR code and prints fallback pairing information to stderr.
func PrintPairingPrompt(w io.Writer, uri string, code ...string) {
	fmt.Fprintln(w, "\nScan this QR code with your peer device to connect:")
	fmt.Fprintln(w)
	_ = RenderQRCodeHalfBlock(w, uri)
	fmt.Fprintln(w)
	if len(code) > 0 && code[0] != "" {
		fmt.Fprintln(w, "Or pair using this short 8-character code:")
		fmt.Fprintf(w, "  psych join %s\n\n", code[0])
	}
	fmt.Fprintln(w, "Or pair manually with full URI (single quotes required to prevent shell '&' splitting):")
	fmt.Fprintf(w, "  psych join '%s'\n\n", uri)
	fmt.Fprintf(w, "Raw URI:\n  %s\n\n", uri)
	fmt.Fprintln(w, "Waiting for peer to connect...")
}
