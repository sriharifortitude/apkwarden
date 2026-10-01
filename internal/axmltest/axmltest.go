// Package axmltest builds compiled binary XML (AXML) for tests.
//
// It is the inverse of internal/axml, written separately so each checks
// the other: the decoder is also run against real APKs, and this encoder
// is how the cases a handful of real apps can't cover get built exactly
// (obfuscated attribute names, both string encodings, malformed input).
// It is a test helper, not a general AXML writer: it emits only what a
// manifest needs.
package axmltest

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"unicode/utf16"
)

const androidNS = "http://schemas.android.com/apk/res/android"

// Attr is an attribute to encode.
type Attr struct {
	Namespace string
	Name      string
	ResID     uint32 // framework resource ID; 0 for none
	Type      uint8
	Data      uint32
	Raw       string // string value, for Type 0x03
}

// El is an element to encode.
type El struct {
	Name     string
	Attrs    []Attr
	Children []*El
}

// Android attribute helpers. IDs are the framework's.
func Bool(name string, id uint32, v bool) Attr {
	d := uint32(0)
	if v {
		d = 0xFFFFFFFF
	}
	return Attr{Namespace: androidNS, Name: name, ResID: id, Type: 0x12, Data: d}
}

func Str(name string, id uint32, v string) Attr {
	return Attr{Namespace: androidNS, Name: name, ResID: id, Type: 0x03, Raw: v}
}

func Int(name string, id uint32, v int) Attr {
	return Attr{Namespace: androidNS, Name: name, ResID: id, Type: 0x10, Data: uint32(v)}
}

// Ref is a resource reference (@bool/..., @xml/...), whose value is not in the manifest.
func Ref(name string, id uint32, resource uint32) Attr {
	return Attr{Namespace: androidNS, Name: name, ResID: id, Type: 0x01, Data: resource}
}

// Options select how the file is encoded.
type Options struct {
	UTF8 bool
	// Obfuscate blanks every attribute-name string, leaving only the
	// resource-ID table to identify attributes, as release-hardening tools do.
	Obfuscate bool
}

type pool struct {
	strs  []string
	index map[string]int
}

func (p *pool) add(s string) int {
	if i, ok := p.index[s]; ok {
		return i
	}
	p.strs = append(p.strs, s)
	p.index[s] = len(p.strs) - 1
	return len(p.strs) - 1
}

func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }
func le16(b []byte, v uint16) []byte { return binary.LittleEndian.AppendUint16(b, v) }

// Encode returns the binary form of root.
func Encode(root *El, opt Options) []byte {
	// Attribute-name strings come first in the pool, in the same order as the
	// resource-ID table, because the format ties the two by position.
	p := &pool{index: map[string]int{}}
	var resIDs []uint32
	attrSlot := map[[2]any]int{}
	var collect func(*El)
	collect = func(e *El) {
		for _, a := range e.Attrs {
			key := [2]any{a.Name, a.ResID}
			if _, ok := attrSlot[key]; ok || a.ResID == 0 {
				continue
			}
			name := a.Name
			if opt.Obfuscate {
				name = ""
			}
			p.strs = append(p.strs, name)
			attrSlot[key] = len(p.strs) - 1
			resIDs = append(resIDs, a.ResID)
		}
		for _, c := range e.Children {
			collect(c)
		}
	}
	collect(root)
	attrIndex := func(a Attr) int {
		if a.ResID != 0 {
			return attrSlot[[2]any{a.Name, a.ResID}]
		}
		return p.add(a.Name)
	}

	nsURI := p.add(androidNS)
	prefix := p.add("android")

	var body []byte
	body = chunkHeader(body, 0x0100, 16, 24)
	body = le32(body, 1) // line
	body = le32(body, 0xFFFFFFFF)
	body = le32(body, uint32(prefix))
	body = le32(body, uint32(nsURI))

	var emit func(*El)
	emit = func(e *El) {
		nameIdx := p.add(e.Name)
		type enc struct {
			ns, name, raw int
			a             Attr
		}
		var encs []enc
		for _, a := range e.Attrs {
			ns := -1
			if a.Namespace != "" {
				ns = p.add(a.Namespace)
			}
			raw := -1
			if a.Type == 0x03 {
				raw = p.add(a.Raw)
			}
			encs = append(encs, enc{ns, attrIndex(a), raw, a})
		}
		size := 16 + 20 + 20*len(encs)
		body = chunkHeader(body, 0x0102, 16, size)
		body = le32(body, 1)
		body = le32(body, 0xFFFFFFFF)
		body = le32(body, 0xFFFFFFFF) // element namespace
		body = le32(body, uint32(nameIdx))
		body = le16(body, 20)
		body = le16(body, 20)
		body = le16(body, uint16(len(encs)))
		body = le16(body, 0)
		body = le16(body, 0)
		body = le16(body, 0)
		for _, x := range encs {
			body = le32(body, uint32(int32(x.ns)))
			body = le32(body, uint32(x.name))
			body = le32(body, uint32(int32(x.raw)))
			body = le16(body, 8)
			body = append(body, 0, x.a.Type)
			body = le32(body, x.a.Data)
		}
		for _, c := range e.Children {
			emit(c)
		}
		body = chunkHeader(body, 0x0103, 16, 24)
		body = le32(body, 1)
		body = le32(body, 0xFFFFFFFF)
		body = le32(body, 0xFFFFFFFF)
		body = le32(body, uint32(nameIdx))
	}
	emit(root)
	body = chunkHeader(body, 0x0101, 16, 24)
	body = le32(body, 1)
	body = le32(body, 0xFFFFFFFF)
	body = le32(body, uint32(prefix))
	body = le32(body, uint32(nsURI))

	poolBytes := encodePool(p.strs, opt.UTF8)

	var res []byte
	if len(resIDs) > 0 {
		res = chunkHeader(res, 0x0180, 8, 8+4*len(resIDs))
		for _, id := range resIDs {
			res = le32(res, id)
		}
	}

	total := 8 + len(poolBytes) + len(res) + len(body)
	out := chunkHeader(nil, 0x0003, 8, total)
	out = append(out, poolBytes...)
	out = append(out, res...)
	return append(out, body...)
}

func chunkHeader(b []byte, typ, headerSize, size int) []byte {
	b = le16(b, uint16(typ))
	b = le16(b, uint16(headerSize))
	return le32(b, uint32(size))
}

func encodePool(strs []string, utf8 bool) []byte {
	var data []byte
	offsets := make([]uint32, len(strs))
	for i, s := range strs {
		offsets[i] = uint32(len(data))
		if utf8 {
			data = appendLen8(data, len([]rune(s)))
			data = appendLen8(data, len(s))
			data = append(data, s...)
			data = append(data, 0)
		} else {
			u := utf16.Encode([]rune(s))
			if len(u) > 0x7FFF {
				data = le16(data, uint16(0x8000|len(u)>>16))
				data = le16(data, uint16(len(u)))
			} else {
				data = le16(data, uint16(len(u)))
			}
			for _, c := range u {
				data = le16(data, c)
			}
			data = le16(data, 0)
		}
	}
	for len(data)%4 != 0 {
		data = append(data, 0)
	}
	headerSize := 28
	stringsStart := headerSize + 4*len(strs)
	size := stringsStart + len(data)
	flags := uint32(0)
	if utf8 {
		flags = 1 << 8
	}
	var b []byte
	b = chunkHeader(b, 0x0001, headerSize, size)
	b = le32(b, uint32(len(strs)))
	b = le32(b, 0) // styles
	b = le32(b, flags)
	b = le32(b, uint32(stringsStart))
	b = le32(b, 0)
	for _, o := range offsets {
		b = le32(b, o)
	}
	return append(b, data...)
}

func appendLen8(b []byte, n int) []byte {
	if n > 0x7F {
		return append(b, byte(0x80|n>>8), byte(n))
	}
	return append(b, byte(n))
}

// APK wraps a manifest in a zip, as an APK does.
func APK(manifest []byte, extra map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("AndroidManifest.xml")
	_, _ = w.Write(manifest)
	for name, data := range extra {
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	return buf.Bytes()
}

// Zip builds an archive from the given files, for inputs that are zips but
// not APKs.
func Zip(files map[string][]byte) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, _ := zw.Create(name)
		_, _ = w.Write(data)
	}
	_ = zw.Close()
	return buf.Bytes()
}
