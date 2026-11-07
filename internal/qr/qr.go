// Package qr renders QR codes for the terminal and for PNG files without a
// qrencode dependency. It only encodes text; it never decodes or validates
// authorization.
package qr

import (
	"fmt"
	"io"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// Terminal writes a QR code using half-block characters, packing two module
// rows into each text row. Modules stay roughly square in a typical terminal,
// but the code uses half the rows and half the columns of a full-block
// rendering. It uses no ANSI colors, so the output also survives logging and
// screen readers that strip styling.
func Terminal(w io.Writer, content string) error {
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("could not encode QR code: %w", err)
	}

	bitmap := code.Bitmap()
	for y := 0; y < len(bitmap); y += 2 {
		top := bitmap[y]
		var bottom []bool
		if y+1 < len(bitmap) {
			bottom = bitmap[y+1]
		}

		var line strings.Builder
		line.Grow(len(top))
		for x, topDark := range top {
			bottomDark := x < len(bottom) && bottom[x]
			switch {
			case topDark && bottomDark:
				line.WriteString("█")
			case topDark:
				line.WriteString("▀")
			case bottomDark:
				line.WriteString("▄")
			default:
				line.WriteString(" ")
			}
		}
		if _, err := io.WriteString(w, line.String()+"\n"); err != nil {
			return err
		}
	}
	return nil
}

// PNG writes a PNG image with the given width and height in pixels. A larger
// image is used if size is too small for the content.
func PNG(w io.Writer, content string, size int) error {
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("could not encode QR code: %w", err)
	}
	if err := code.Write(size, w); err != nil {
		return fmt.Errorf("could not write PNG: %w", err)
	}
	return nil
}
