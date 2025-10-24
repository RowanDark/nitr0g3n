package probe

import (
	"bytes"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

func renderScreenshot(lines []string) ([]byte, error) {
	if len(lines) == 0 {
		lines = []string{"nitr0g3n probe"}
	}

	width := 800
	lineHeight := 20
	padding := 16
	height := padding*2 + lineHeight*len(lines)

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	draw.Draw(img, img.Bounds(), &image.Uniform{C: color.RGBA{18, 18, 18, 255}}, image.Point{}, draw.Src)

	face := basicfont.Face7x13
	drawer := font.Drawer{Dst: img, Face: face, Src: image.NewUniform(color.RGBA{220, 220, 220, 255})}

	for i, line := range lines {
		drawer.Dot = fixed.Point26_6{X: fixed.I(padding), Y: fixed.I(padding + (i+1)*lineHeight)}
		drawer.DrawString(line)
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sanitizeFilename(name string) string {
	if name == "" {
		return "unknown"
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_' || r == '.':
			return r
		default:
			return '_'
		}
	}, name)
	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		return "unknown"
	}
	return cleaned
}
