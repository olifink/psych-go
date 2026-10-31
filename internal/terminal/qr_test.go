package terminal

import (
	"bytes"
	"strings"
	"testing"
)

func TestRenderQRCodeHalfBlock(t *testing.T) {
	var buf bytes.Buffer
	testURI := "psych://pair?v=1&sid=0123456789abcdef0123456789abcdef&relay=ws%3A%2F%2F127.0.0.1%3A8080%2Fws&pub=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	err := RenderQRCodeHalfBlock(&buf, testURI)
	if err != nil {
		t.Fatalf("render QR failed: %v", err)
	}

	rendered := buf.String()
	if len(rendered) == 0 {
		t.Fatal("rendered QR output is empty")
	}

	// Verify half blocks or full blocks are present in output
	if !strings.ContainsRune(rendered, CharUpperBlock) &&
		!strings.ContainsRune(rendered, CharLowerBlock) &&
		!strings.ContainsRune(rendered, CharFullBlock) {
		t.Fatal("expected rendered output to contain Unicode half blocks or full blocks")
	}

	lines := strings.Split(strings.TrimSpace(rendered), "\n")
	// For standard QR codes with ~33x33 modules + margin, half blocks make it ~19-25 lines tall
	if len(lines) > 30 {
		t.Fatalf("rendered QR too tall for standard 80x24 terminal: %d lines", len(lines))
	}
}
