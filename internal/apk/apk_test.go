package apk

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/axmltest"
)

func zipOf(files map[string][]byte) []byte { return axmltest.Zip(files) }

func TestFindsTheManifestAtTheRoot(t *testing.T) {
	got, err := ManifestFrom(zipOf(map[string][]byte{
		"classes.dex":         []byte("dex"),
		"AndroidManifest.xml": []byte("the manifest"),
	}))
	if err != nil || string(got) != "the manifest" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestIgnoresAManifestThatIsNotAtTheRoot(t *testing.T) {
	_, err := ManifestFrom(zipOf(map[string][]byte{
		"assets/AndroidManifest.xml":  []byte("not it"),
		"res/AndroidManifest.xml.bak": []byte("not it either"),
	}))
	if !errors.Is(err, ErrNoManifest) {
		t.Errorf("err = %v, want ErrNoManifest", err)
	}
}

func TestBareManifestPassesThrough(t *testing.T) {
	got, err := ManifestFrom([]byte{3, 0, 8, 0, 1, 2, 3, 4})
	if err != nil || len(got) != 8 {
		t.Errorf("got %v, %v", got, err)
	}
}

// A zip entry can declare any size and be tiny on disk. An honest-header
// bomb is refused before anything is decompressed.
func TestRefusesAManifestThatDeclaresMoreThanTheLimit(t *testing.T) {
	huge := bytes.Repeat([]byte{0}, maxManifestSize+1) // compresses to a few KB
	_, err := ManifestFrom(zipOf(map[string][]byte{"AndroidManifest.xml": huge}))
	if err == nil || !strings.Contains(err.Error(), "over the") {
		t.Errorf("err = %v, want a size-limit error", err)
	}
}

func TestAManifestAtTheLimitIsStillRead(t *testing.T) {
	data := bytes.Repeat([]byte{7}, maxManifestSize)
	got, err := ManifestFrom(zipOf(map[string][]byte{"AndroidManifest.xml": data}))
	if err != nil || len(got) != maxManifestSize {
		t.Errorf("a manifest of exactly the limit should be read: %d bytes, %v", len(got), err)
	}
}

func TestCorruptZipIsAnErrorNotAPanic(t *testing.T) {
	good := zipOf(map[string][]byte{"AndroidManifest.xml": []byte("x")})
	for n := 2; n < len(good); n += 7 {
		// Starts with PK, but is cut short: the central directory is gone.
		if _, err := ManifestFrom(good[:n]); err == nil {
			t.Fatalf("a %d-byte prefix of a zip was accepted", n)
		}
	}
}
