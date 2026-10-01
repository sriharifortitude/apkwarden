package axml_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/sriharifortitude/apkwarden/internal/axml"
	"github.com/sriharifortitude/apkwarden/internal/axmltest"
)

func sample() *axmltest.El {
	return &axmltest.El{
		Name:  "manifest",
		Attrs: []axmltest.Attr{{Name: "package", Type: 0x03, Raw: "com.example.app"}},
		Children: []*axmltest.El{{
			Name: "application",
			Attrs: []axmltest.Attr{
				axmltest.Bool("debuggable", 0x0101000f, true),
				axmltest.Str("label", 0x01010001, "Ünïcode 株式会社 label"),
				axmltest.Int("minSdkVersion", 0x0101020c, 23),
			},
			Children: []*axmltest.El{{Name: "activity"}},
		}},
	}
}

func TestRoundTripInBothStringEncodings(t *testing.T) {
	for _, utf8 := range []bool{false, true} {
		doc, err := axml.Parse(axmltest.Encode(sample(), axmltest.Options{UTF8: utf8}))
		if err != nil {
			t.Fatalf("utf8=%v: %v", utf8, err)
		}
		if doc.Root.Name != "manifest" || len(doc.Root.Children) != 1 {
			t.Fatalf("utf8=%v: tree shape wrong: %+v", utf8, doc.Root)
		}
		app := doc.Root.Children[0]
		if app.Name != "application" || len(app.Children) != 1 || app.Children[0].Name != "activity" {
			t.Fatalf("utf8=%v: application subtree wrong", utf8)
		}
		var label string
		for _, a := range app.Attrs {
			if a.Name == "label" {
				label = a.Raw
			}
			if a.Name == "debuggable" && (a.DataType != axml.TypeBoolean || a.Data != 0xFFFFFFFF) {
				t.Errorf("utf8=%v: debuggable decoded as type %#x data %#x", utf8, a.DataType, a.Data)
			}
		}
		if label != "Ünïcode 株式会社 label" {
			t.Errorf("utf8=%v: label = %q", utf8, label)
		}
	}
}

func TestLongStringsUseTheTwoPartLengthEncoding(t *testing.T) {
	long := strings.Repeat("é", 300) // above the 127 limit of a one-byte UTF-8 length
	root := &axmltest.El{Name: "manifest", Attrs: []axmltest.Attr{axmltest.Str("name", 0x01010003, long)}}
	for _, utf8 := range []bool{false, true} {
		doc, err := axml.Parse(axmltest.Encode(root, axmltest.Options{UTF8: utf8}))
		if err != nil {
			t.Fatalf("utf8=%v: %v", utf8, err)
		}
		if got := doc.Root.Attrs[0].Raw; got != long {
			t.Errorf("utf8=%v: got %d chars, want %d", utf8, len([]rune(got)), len([]rune(long)))
		}
	}
}

func TestObfuscatedNamesKeepTheirResourceID(t *testing.T) {
	doc, err := axml.Parse(axmltest.Encode(sample(), axmltest.Options{Obfuscate: true}))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range doc.Root.Children[0].Attrs {
		if a.Name != "" {
			t.Errorf("attribute name should be blank when obfuscated, got %q", a.Name)
		}
		if a.ResourceID == 0 {
			t.Errorf("attribute lost its resource ID")
		}
	}
	if got := doc.Root.Children[0].Attrs[0].ResourceID; got != 0x0101000f {
		t.Errorf("first attribute ID = %#x, want debuggable's 0x0101000f", got)
	}
}

func TestNotAXML(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":      nil,
		"short":      {1, 2, 3},
		"plain xml":  []byte(`<?xml version="1.0"?><manifest/>`),
		"zip header": []byte("PK\x03\x04 and so on"),
	} {
		if _, err := axml.Parse(data); !errors.Is(err, axml.ErrNotAXML) {
			t.Errorf("%s: err = %v, want ErrNotAXML", name, err)
		}
	}
}

// Every proper prefix of a valid file must be refused cleanly, never
// panic and never be accepted as a document.
func TestEveryTruncationIsRefused(t *testing.T) {
	full := axmltest.Encode(sample(), axmltest.Options{})
	for n := 0; n < len(full); n++ {
		if _, err := axml.Parse(full[:n]); err == nil {
			t.Fatalf("a %d-byte prefix of a %d-byte file was accepted", n, len(full))
		}
	}
}

func TestCorruptedFieldsAreRefusedWithAnOffset(t *testing.T) {
	good := axmltest.Encode(sample(), axmltest.Options{})
	cases := map[string]func([]byte){
		"string count huge": func(b []byte) { b[8+8] = 0xFF; b[8+9] = 0xFF; b[8+10] = 0xFF; b[8+11] = 0x7F },
		"chunk size zero":   func(b []byte) { b[8+4], b[8+5], b[8+6], b[8+7] = 0, 0, 0, 0 },
		"chunk past end":    func(b []byte) { b[8+4], b[8+5], b[8+6], b[8+7] = 0xFF, 0xFF, 0xFF, 0x00 },
	}
	for name, mutate := range cases {
		b := append([]byte(nil), good...)
		mutate(b)
		_, err := axml.Parse(b)
		var e *axml.Error
		if !errors.As(err, &e) {
			t.Errorf("%s: err = %v, want an *axml.Error", name, err)
		}
	}
}

func TestDeepNestingIsRefusedNotRecursedInto(t *testing.T) {
	root := &axmltest.El{Name: "manifest"}
	cur := root
	for i := 0; i < 400; i++ {
		next := &axmltest.El{Name: "x"}
		cur.Children = []*axmltest.El{next}
		cur = next
	}
	if _, err := axml.Parse(axmltest.Encode(root, axmltest.Options{})); err == nil || !strings.Contains(err.Error(), "nested deeper") {
		t.Fatalf("err = %v, want a nesting-depth error", err)
	}
}

func FuzzParse(f *testing.F) {
	f.Add(axmltest.Encode(sample(), axmltest.Options{}))
	f.Add(axmltest.Encode(sample(), axmltest.Options{UTF8: true, Obfuscate: true}))
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only requirement is that it returns: no panic, no hang, no
		// unbounded allocation. The result is irrelevant.
		doc, err := axml.Parse(data)
		if err == nil && doc.Root == nil {
			t.Fatal("nil error with no root")
		}
	})
}

// A string whose declared length runs past the end of its pool but still
// lands inside the file (the pool is followed by more chunks) must be
// refused. Reading it would decode other chunks' bytes as text.
func TestStringLengthPastThePoolButInsideTheFileIsRefused(t *testing.T) {
	for _, utf8 := range []bool{false, true} {
		b := axmltest.Encode(sample(), axmltest.Options{UTF8: utf8})
		le32 := func(off int) int { return int(b[off]) | int(b[off+1])<<8 | int(b[off+2])<<16 | int(b[off+3])<<24 }
		const pool = 8
		count := le32(pool + 8)
		stringsStart := le32(pool + 20)
		offsets := pool + 28
		last := pool + stringsStart + le32(offsets+4*(count-1))
		if utf8 {
			b[last+1] = 120 // byte length: far more than is left in the pool
		} else {
			b[last], b[last+1] = 120, 0 // 120 UTF-16 units
		}
		_, err := axml.Parse(b)
		if err == nil || !strings.Contains(err.Error(), "runs past the pool") {
			t.Errorf("utf8=%v: err = %v, want a runs-past-the-pool error", utf8, err)
		}
	}
}
