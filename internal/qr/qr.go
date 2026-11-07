// Package qr renders QR codes for the terminal and for PNG files without a
// qrencode dependency. It only encodes text; it never decodes or validates
// authorization.
package qr

import (
	"fmt"
	"io"

	qrcode "github.com/skip2/go-qrcode"
)

// Terminal writes a QR code that uses two character cells per module so it
// stays roughly square in a typical terminal. It uses no ANSI colors, so the
// output also survives logging and screen readers that strip styling.
func Terminal(w io.Writer, content string) error {
	code, err := qrcode.New(content, qrcode.Medium)
	if err != nil {
		return fmt.Errorf("could not encode QR code: %w", err)
	}

	for _, row := range code.Bitmap() {
		for _, dark := range row {
			if dark {
				if _, err := io.WriteString(w, "██"); err != nil {
					return err
				}
				continue
			}
			if _, err := io.WriteString(w, "  "); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
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
