package main

import (
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/apk"
	"github.com/sriharifortitude/apkwarden/internal/axml"
	"github.com/sriharifortitude/apkwarden/internal/axmltest"
	"github.com/sriharifortitude/apkwarden/internal/manifest"
	"github.com/sriharifortitude/apkwarden/internal/rules"
)

// An APK is attacker-supplied. Whatever bytes arrive, the whole path
// (zip, decoder, manifest model, every rule) must return, never panic.
func FuzzWholePipeline(f *testing.F) {
	root := manifestEl(receiverApp())
	f.Add(axmltest.Encode(root, axmltest.Options{}))
	f.Add(axmltest.Encode(root, axmltest.Options{UTF8: true, Obfuscate: true}))
	f.Add(axmltest.APK(axmltest.Encode(manifestEl(debuggableApp()), axmltest.Options{}), nil))
	f.Fuzz(func(t *testing.T, data []byte) {
		raw, err := apk.ManifestFrom(data)
		if err != nil {
			return
		}
		doc, err := axml.Parse(raw)
		if err != nil {
			return
		}
		m, err := manifest.Parse(doc)
		if err != nil {
			return
		}
		rules.RunAll(m, rules.DefaultConfig())
	})
}
