package collect

import (
	"bytes"
	"context"
	"encoding/binary"
	"image/png"
	"os"
	"path/filepath"
	"strings"
)

// An icon is outside data like everything else in a bundle, so these bound what it can cost.
const (
	maxIconFile = 32 << 20
	maxIconSide = 2048
)

// The sizes worth showing, best first: a card draws about 40 points, so 80 pixels on a sharp screen. The
// larger ones are fine, just heavier; the small ones are a last resort.
var iconSizes = []string{"ic07", "ic13", "ic08", "ic14", "ic09", "ic10", "ic12", "ic11"}

var pngMagic = []byte("\x89PNG\r\n\x1a\n")

// ParseICNS splits an Apple icon file into its entries by type. The format is a magic number, a total length,
// then type-and-length records. Anything inconsistent ends the parse; what came before it still counts.
func ParseICNS(b []byte) map[string][]byte {
	out := map[string][]byte{}
	if len(b) < 8 || string(b[:4]) != "icns" {
		return out
	}
	end := len(b)
	if total := binary.BigEndian.Uint32(b[4:8]); uint64(total) < uint64(end) {
		end = int(total)
	}
	for at := 8; at+8 <= end; {
		size := binary.BigEndian.Uint32(b[at+4 : at+8])
		if size < 8 || uint64(at)+uint64(size) > uint64(end) {
			break
		}
		out[string(b[at:at+4])] = b[at+8 : at+int(size)]
		at += int(size)
	}
	return out
}

// bestIcon picks the first preferred size holding a PNG that really is one, of a sane size.
func bestIcon(entries map[string][]byte) []byte {
	for _, kind := range iconSizes {
		d := entries[kind]
		if !bytes.HasPrefix(d, pngMagic) {
			continue
		}
		cfg, err := png.DecodeConfig(bytes.NewReader(d))
		if err != nil || cfg.Width > maxIconSide || cfg.Height > maxIconSide {
			continue
		}
		if _, err := png.Decode(bytes.NewReader(d)); err != nil {
			continue
		}
		return d
	}
	return nil
}

// ReadIcon returns the PNG an app bundle ships as its icon, or nil if it doesn't have a usable one. It follows
// what the bundle itself declares, so it needs no list of apps. The declared name is outside data: only its
// base name is used and the file must be a regular one, so a bundle can't point this elsewhere on disk.
func ReadIcon(ctx context.Context, app string) []byte {
	name := filepath.Base(plistValue(ctx, filepath.Join(app, "Contents/Info.plist"), "CFBundleIconFile"))
	if name == "." || name == string(filepath.Separator) {
		return nil
	}
	if !strings.HasSuffix(name, ".icns") {
		name += ".icns"
	}
	p := filepath.Join(app, "Contents/Resources", name)
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > maxIconFile {
		return nil
	}
	b, err := os.ReadFile(p) // #nosec G304 -- a regular file directly inside a bundle under the apps folders
	if err != nil {
		return nil
	}
	return bestIcon(ParseICNS(b))
}
