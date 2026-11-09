package collect

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseBrewDropsWhatsAlreadyPatched(t *testing.T) {
	r, err := ParseBrew([]byte(`{"checked":83,"complete":false,"skipped_formulae":["a"],"findings":[
		{"formula":"openjpeg","version":"2.5.4","vulnerabilities":[],"patched":[{"id":"CVE-1"}]},
		{"formula":"poppler","version":"26.10.0","vulnerabilities":[{"id":"CVE-2","severity":"UNKNOWN","summary":"s"}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 1 || r.Findings[0].Formula != "poppler" || r.Checked != 83 || r.Complete || len(r.Skipped) != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestExposureOverlay(t *testing.T) {
	dir := t.TempDir()
	if m, err := LoadExposure(dir); err != nil || m != nil {
		t.Fatal(m, err)
	}
	p := filepath.Join(dir, "exposure.json")
	if err := os.WriteFile(p, []byte(`{"format":1,"apps":{"X.app":{"rank":3,"why":"w"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := LoadExposure(dir)
	if err != nil || m["X.app"].Rank != 3 {
		t.Fatal(m, err)
	}
	if err := os.WriteFile(p, []byte(`{"format":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadExposure(dir); err == nil {
		t.Fatal("an unknown format must be refused")
	}
}

func TestParseLastUsed(t *testing.T) {
	at := time.Date(2026, 6, 20, 6, 33, 13, 0, time.UTC)
	stamp := at.Format("2006-01-02 15:04:05 -0700")
	for _, c := range []struct{ date, count, want string }{
		{stamp, "5", at.Local().Format(time.DateOnly)},
		{stamp, "(null)", ""}, // the date is only the modified time: this app has no usage record
		{stamp, "", ""},
		{stamp, "0", ""},
		{"(null)", "(null)", ""},
		{"not a date", "5", ""},
	} {
		if got := parseLastUsed(c.date, c.count); got != c.want {
			t.Errorf("%q, %q: got %q, want %q", c.date, c.count, got, c.want)
		}
	}
}

func TestReadBundle(t *testing.T) {
	app := filepath.Join(t.TempDir(), "X.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents"), 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>1.2.3</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	then := time.Date(2022, 10, 27, 12, 0, 0, 0, time.Local)
	if err := os.Chtimes(app, then, then); err != nil {
		t.Fatal(err)
	}
	f := ReadBundle(context.Background(), app)
	if f.Version != "1.2.3" || f.Updated != "2022-10-27" || f.LastOpened != "" {
		t.Fatalf("%+v", f)
	}
	if got := ReadBundle(context.Background(), filepath.Join(app, "missing.app")); got.Version != "" || got.Updated != "" || got.LastOpened != "" || got.Icon != nil {
		t.Fatalf("a missing bundle should be all unknown: %+v", got)
	}
}

func FuzzParseLastUsed(f *testing.F) {
	f.Add("2026-06-20 06:33:13 +0000", "5")
	f.Add("(null)", "(null)")
	f.Fuzz(func(_ *testing.T, date, count string) { _ = parseLastUsed(date, count) })
}

func testPNG(t *testing.T, side int) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, side, side))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func icns(entries ...any) []byte {
	var body bytes.Buffer
	for i := 0; i+1 < len(entries); i += 2 {
		d := entries[i+1].([]byte)
		body.WriteString(entries[i].(string))
		_ = binary.Write(&body, binary.BigEndian, uint32(len(d)+8)) // #nosec G115 -- test data
		body.Write(d)
	}
	var out bytes.Buffer
	out.WriteString("icns")
	_ = binary.Write(&out, binary.BigEndian, uint32(body.Len()+8)) // #nosec G115 -- test data
	out.Write(body.Bytes())
	return out.Bytes()
}

func bundleWithIcon(t *testing.T, declared string, file []byte) string {
	t.Helper()
	app := filepath.Join(t.TempDir(), "X.app")
	if err := os.MkdirAll(filepath.Join(app, "Contents/Resources"), 0o700); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIconFile</key><string>` + declared + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte(plist), 0o600); err != nil {
		t.Fatal(err)
	}
	if file != nil {
		if err := os.WriteFile(filepath.Join(app, "Contents/Resources/shipped.icns"), file, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return app
}

func TestReadIconFollowsWhatTheBundleDeclares(t *testing.T) {
	want := testPNG(t, 128)
	file := icns("ic12", testPNG(t, 64), "ic07", want, "ic09", testPNG(t, 512), "info", []byte("x"))
	ctx := context.Background()
	for _, declared := range []string{"shipped.icns", "shipped"} {
		if got := ReadIcon(ctx, bundleWithIcon(t, declared, file)); !bytes.Equal(got, want) {
			t.Fatalf("%q: got %d bytes, want the 128px entry", declared, len(got))
		}
	}
}

func TestReadIconTakesNoBadInput(t *testing.T) {
	ctx := context.Background()
	notAPNG := append(append([]byte{}, pngMagic...), []byte("then garbage")...)
	var huge bytes.Buffer
	huge.Write(pngMagic)
	_ = binary.Write(&huge, binary.BigEndian, uint32(13))
	huge.WriteString("IHDR")
	_ = binary.Write(&huge, binary.BigEndian, uint32(100000))
	_ = binary.Write(&huge, binary.BigEndian, uint32(100000))
	huge.Write([]byte{8, 6, 0, 0, 0, 0, 0, 0, 0})
	for name, file := range map[string][]byte{
		"not an icon file": []byte("hello"),
		"empty":            {},
		"no PNG inside":    icns("ic04", []byte("raw pixels")),
		"a fake PNG":       icns("ic07", notAPNG),
		"an absurd size":   icns("ic07", huge.Bytes()),
	} {
		if got := ReadIcon(ctx, bundleWithIcon(t, "shipped.icns", file)); got != nil {
			t.Errorf("%s: got %d bytes", name, len(got))
		}
	}
	if got := ReadIcon(ctx, bundleWithIcon(t, "missing.icns", nil)); got != nil {
		t.Error("a missing file")
	}
}

func TestABundleCantPointTheIconElsewhere(t *testing.T) {
	ctx := context.Background()
	secret := filepath.Join(t.TempDir(), "secret.icns")
	if err := os.WriteFile(secret, icns("ic07", testPNG(t, 128)), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := ReadIcon(ctx, bundleWithIcon(t, "../../../"+filepath.Base(secret), nil)); got != nil {
		t.Fatal("a declared path must not leave the bundle")
	}
	if got := ReadIcon(ctx, bundleWithIcon(t, secret, nil)); got != nil {
		t.Fatal("an absolute declared path must not leave the bundle")
	}
	app := bundleWithIcon(t, "linked.icns", nil)
	if err := os.Symlink(secret, filepath.Join(app, "Contents/Resources/linked.icns")); err != nil {
		t.Fatal(err)
	}
	if got := ReadIcon(ctx, app); got != nil {
		t.Fatal("a symlink must not be followed")
	}
}

func FuzzParseICNS(f *testing.F) {
	f.Add(icns("ic07", []byte("x"), "ic08", []byte("yy")))
	f.Add([]byte("icns\x00\x00\x00\x10ic07\x00\x00\x00\x00"))
	f.Add([]byte("icns\xff\xff\xff\xffic07\xff\xff\xff\xff"))
	f.Fuzz(func(t *testing.T, b []byte) {
		for kind, d := range ParseICNS(b) {
			if len(kind) != 4 || len(d) > len(b) {
				t.Fatalf("%q: %d bytes from %d", kind, len(d), len(b))
			}
		}
		_ = bestIcon(ParseICNS(b))
	})
}

func FuzzParseBrew(f *testing.F) {
	f.Add([]byte(`{"findings":[{"formula":"x","vulnerabilities":[{"id":"y"}]}]}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseBrew(b) })
}

const softwareUpdateSample = `Software Update found the following new or updated software:
* Label: Browser1.2Auto-1.2
	Title: Browser, Version: 1.2, Size: 250130KiB, Recommended: YES, 
* Label: macOS Example 26.7.2-25G332
	Title: macOS Example 26.7.2, Version: 26.7.2, Size: 3111224KiB, Recommended: YES, Action: restart, 
`

func TestParseSoftwareUpdates(t *testing.T) {
	got := ParseSoftwareUpdates(softwareUpdateSample)
	if len(got) != 2 || got[0].Name != "Browser" || got[0].Latest != "1.2" || got[0].Restart {
		t.Fatalf("%+v", got)
	}
	if got[1].Name != "macOS Example 26.7.2" || got[1].Latest != "26.7.2" || !got[1].Restart {
		t.Fatalf("%+v", got[1])
	}
	if got := ParseSoftwareUpdates("No new software available.\n"); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func FuzzParseSoftwareUpdates(f *testing.F) {
	f.Add(softwareUpdateSample)
	f.Fuzz(func(_ *testing.T, s string) { _ = ParseSoftwareUpdates(s) })
}

func TestParseOutdated(t *testing.T) {
	got, err := ParseOutdated([]byte(`{"formulae":[
		{"name":"uv","installed_versions":["0.1","0.2"],"current_version":"0.3"},
		{"name":"tap/x/tool","installed_versions":["1"],"current_version":"2"},
		{"name":"held","installed_versions":["1"],"current_version":"2","pinned":true},
		{"name":"--force","installed_versions":["1"],"current_version":"2"},
		{"name":"no-version","installed_versions":["1"],"current_version":""}
	],"casks":[{"name":"ignored"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "uv" || got[0].Installed != "0.2" || got[0].Latest != "0.3" || got[1].Name != "tap/x/tool" {
		t.Fatalf("%+v", got)
	}
}

func FuzzParseOutdated(f *testing.F) {
	f.Add([]byte(`{"formulae":[{"name":"uv","installed_versions":["1"],"current_version":"2"}]}`))
	f.Fuzz(func(_ *testing.T, b []byte) { _, _ = ParseOutdated(b) })
}
