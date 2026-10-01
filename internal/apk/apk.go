// Package apk finds AndroidManifest.xml inside an APK, or accepts one
// already extracted.
package apk

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxManifestSize bounds how much is read for the manifest entry. Real
// compiled manifests are tens to a few hundred kilobytes; the limit is
// there because the size a zip entry declares is the attacker's to choose.
const maxManifestSize = 16 << 20

const manifestName = "AndroidManifest.xml"

// ErrNoManifest is returned for a valid zip with no AndroidManifest.xml
// at its root, which is what an app bundle (.aab), a split config APK
// without one, or any other zip looks like.
var ErrNoManifest = errors.New("no AndroidManifest.xml at the root of the archive")

// ReadManifest returns the compiled manifest from the file at path, which
// may be an APK or a bare AndroidManifest.xml in binary form.
func ReadManifest(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ManifestFrom(data)
}

// ManifestFrom is ReadManifest over bytes already in memory.
func ManifestFrom(data []byte) ([]byte, error) {
	if len(data) >= 2 && data[0] == 'P' && data[1] == 'K' {
		return fromZip(data)
	}
	// Not a zip: treat as a bare manifest and let the decoder decide.
	return data, nil
}

func fromZip(data []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a readable zip archive: %w", err)
	}
	for _, f := range zr.File {
		// Exact name, at the root: an APK holds one manifest, and a file
		// called assets/AndroidManifest.xml is not it.
		if f.Name != manifestName {
			continue
		}
		if f.UncompressedSize64 > maxManifestSize {
			return nil, fmt.Errorf("%s declares %d bytes, over the %d byte limit", manifestName, f.UncompressedSize64, maxManifestSize)
		}
		rc, err := f.Open()
		if err != nil {
			return nil, fmt.Errorf("opening %s: %w", manifestName, err)
		}
		defer rc.Close()
		// Read one byte past the limit: the header's declared size can lie.
		out, err := io.ReadAll(io.LimitReader(rc, maxManifestSize+1))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", manifestName, err)
		}
		if len(out) > maxManifestSize {
			return nil, fmt.Errorf("%s decompresses to more than %d bytes", manifestName, maxManifestSize)
		}
		return out, nil
	}
	return nil, ErrNoManifest
}
