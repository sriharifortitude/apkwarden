// Package axml decodes Android's compiled binary XML ("AXML"), the format
// AndroidManifest.xml is stored in inside an APK.
//
// The format is a sequence of little-endian chunks, each starting with a
// header of (type uint16, headerSize uint16, size uint32). A file is one
// RES_XML chunk containing a string pool, an optional table mapping
// attribute names to Android resource IDs, and then a stream of
// namespace, element start/end and text chunks. Strings are referenced by
// index everywhere, so the pool is decoded first and the tree built from
// the stream.
//
// An APK is attacker-supplied input: a malicious one can claim a billion
// strings, point an offset past the end of the file, or nest elements
// until the stack runs out. Every read is bounds-checked and every count
// and depth is capped, and Parse returns an error instead of panicking on
// anything malformed. FuzzParse in this package holds it to that.
package axml

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf16"
)

// Chunk types, from frameworks/base/include/androidfw/ResourceTypes.h.
const (
	typeStringPool     = 0x0001
	typeXML            = 0x0003
	typeStartNamespace = 0x0100
	typeEndNamespace   = 0x0101
	typeStartElement   = 0x0102
	typeEndElement     = 0x0103
	typeCData          = 0x0104
	typeResourceMap    = 0x0180
)

// Value types of a typed attribute (Res_value::dataType).
const (
	TypeNull      = 0x00
	TypeReference = 0x01
	TypeAttribute = 0x02
	TypeString    = 0x03
	TypeFloat     = 0x04
	TypeDimension = 0x05
	TypeFraction  = 0x06
	TypeIntDec    = 0x10
	TypeIntHex    = 0x11
	TypeBoolean   = 0x12
)

// Limits. Real manifests are far below all of them: the largest ones seen
// in the wild have a few thousand strings and nest under thirty deep.
const (
	maxStrings    = 1 << 20
	maxDepth      = 256
	maxAttributes = 1 << 12
	maxElements   = 1 << 20
)

const noIndex = 0xFFFFFFFF

// Attr is one attribute of an element.
type Attr struct {
	Namespace string // namespace URI, "" for none
	Name      string
	// ResourceID is the Android resource ID of the attribute (0x0101xxxx
	// for framework attributes), or 0. Obfuscators blank the name string
	// but have to leave this, since the runtime finds attributes by it.
	ResourceID uint32
	DataType   uint8
	Data       uint32
	// Raw is the string form of the value when the file stores one (always
	// for TypeString), else "".
	Raw string
}

// IsAndroid reports whether the attribute is in the android namespace.
func (a Attr) IsAndroid() bool { return a.Namespace == AndroidNS }

// AndroidNS is the namespace of framework attributes.
const AndroidNS = "http://schemas.android.com/apk/res/android"

// Element is a node of the decoded tree.
type Element struct {
	Name     string
	Attrs    []Attr
	Children []*Element
}

// Document is a decoded file.
type Document struct {
	Root *Element
}

// Error is returned for every malformed input, with the byte offset the
// problem was found at.
type Error struct {
	Offset int
	Msg    string
}

func (e *Error) Error() string { return fmt.Sprintf("axml: offset %d: %s", e.Offset, e.Msg) }

func fail(off int, format string, args ...any) error {
	return &Error{Offset: off, Msg: fmt.Sprintf(format, args...)}
}

// ErrNotAXML is returned when the data doesn't start with a RES_XML chunk,
// which is the usual sign of a plain-text XML manifest or a wrong file.
var ErrNotAXML = errors.New("axml: not a compiled binary XML file")

type reader struct {
	data []byte
}

func (r reader) u16(off int) (uint16, error) {
	if off < 0 || off+2 > len(r.data) {
		return 0, fail(off, "read past end of data")
	}
	return binary.LittleEndian.Uint16(r.data[off:]), nil
}

func (r reader) u32(off int) (uint32, error) {
	if off < 0 || off+4 > len(r.data) {
		return 0, fail(off, "read past end of data")
	}
	return binary.LittleEndian.Uint32(r.data[off:]), nil
}

type chunk struct {
	typ        uint16
	headerSize int
	start, end int // absolute offsets: [start, end)
}

func (r reader) chunkAt(off, limit int) (chunk, error) {
	typ, err := r.u16(off)
	if err != nil {
		return chunk{}, err
	}
	hs, err := r.u16(off + 2)
	if err != nil {
		return chunk{}, err
	}
	size, err := r.u32(off + 4)
	if err != nil {
		return chunk{}, err
	}
	end := off + int(size)
	if int(size) < 8 || int(hs) < 8 || int(hs) > int(size) || end > limit || end < off {
		return chunk{}, fail(off, "chunk 0x%04x has size %d / header %d inside %d available bytes", typ, size, hs, limit-off)
	}
	return chunk{typ: typ, headerSize: int(hs), start: off, end: end}, nil
}

// Parse decodes a binary XML document.
func Parse(data []byte) (*Document, error) {
	r := reader{data}
	if len(data) < 8 {
		return nil, ErrNotAXML
	}
	if t, _ := r.u16(0); t != typeXML {
		return nil, ErrNotAXML
	}
	top, err := r.chunkAt(0, len(data))
	if err != nil {
		return nil, err
	}

	var (
		pool    []string
		resIDs  []uint32
		haveRes bool
		stack   []*Element
		root    *Element
		count   int
	)

	off := top.start + top.headerSize
	for off < top.end {
		c, err := r.chunkAt(off, top.end)
		if err != nil {
			return nil, err
		}
		switch c.typ {
		case typeStringPool:
			if pool != nil {
				return nil, fail(off, "second string pool")
			}
			pool, err = r.stringPool(c)
			if err != nil {
				return nil, err
			}
		case typeResourceMap:
			n := (c.end - c.start - c.headerSize) / 4
			resIDs = make([]uint32, n)
			for i := range resIDs {
				resIDs[i], _ = r.u32(c.start + c.headerSize + 4*i)
			}
			haveRes = true
		case typeStartNamespace, typeEndNamespace, typeCData:
			// Namespaces are resolved through the URI index stored on each
			// attribute, so these carry nothing the tree needs.
		case typeStartElement:
			if pool == nil {
				return nil, fail(off, "element before the string pool")
			}
			count++
			if count > maxElements {
				return nil, fail(off, "more than %d elements", maxElements)
			}
			el, err := r.startElement(c, pool, resIDs, haveRes)
			if err != nil {
				return nil, err
			}
			if len(stack) >= maxDepth {
				return nil, fail(off, "elements nested deeper than %d", maxDepth)
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, el)
			} else if root != nil {
				return nil, fail(off, "more than one root element")
			} else {
				root = el
			}
			stack = append(stack, el)
		case typeEndElement:
			if len(stack) == 0 {
				return nil, fail(off, "end element with none open")
			}
			stack = stack[:len(stack)-1]
		default:
			// Unknown chunk types are skipped, as the Android runtime does.
		}
		off = c.end
	}
	if root == nil {
		return nil, fail(top.start, "document has no root element")
	}
	if len(stack) != 0 {
		return nil, fail(top.end, "%d element(s) never closed", len(stack))
	}
	return &Document{Root: root}, nil
}

func (r reader) stringPool(c chunk) ([]string, error) {
	h := c.start + 8
	count, err := r.u32(h)
	if err != nil {
		return nil, err
	}
	styleCount, err := r.u32(h + 4)
	if err != nil {
		return nil, err
	}
	flags, err := r.u32(h + 8)
	if err != nil {
		return nil, err
	}
	stringsStart, err := r.u32(h + 12)
	if err != nil {
		return nil, err
	}
	if count > maxStrings || styleCount > maxStrings {
		return nil, fail(c.start, "string pool claims %d strings and %d styles", count, styleCount)
	}
	utf8 := flags&(1<<8) != 0

	offsets := c.start + c.headerSize
	if offsets+4*int(count) > c.end {
		return nil, fail(offsets, "string offset table runs past the pool")
	}
	base := c.start + int(stringsStart)
	if int(stringsStart) < c.headerSize || base > c.end {
		return nil, fail(c.start, "strings start at %d, outside the pool", stringsStart)
	}

	out := make([]string, count)
	for i := range out {
		rel, _ := r.u32(offsets + 4*i)
		at := base + int(rel)
		if at < base || at >= c.end {
			return nil, fail(offsets+4*i, "string %d starts outside the pool", i)
		}
		var s string
		if utf8 {
			s, err = r.utf8String(at, c.end)
		} else {
			s, err = r.utf16String(at, c.end)
		}
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

// utf16String reads a length-prefixed UTF-16LE string: one uint16 of
// code units, or two if the first has its top bit set.
func (r reader) utf16String(off, limit int) (string, error) {
	n, err := r.u16(off)
	if err != nil {
		return "", err
	}
	off += 2
	length := int(n)
	if n&0x8000 != 0 {
		lo, err := r.u16(off)
		if err != nil {
			return "", err
		}
		off += 2
		length = int(n&0x7FFF)<<16 | int(lo)
	}
	if off+2*length > limit {
		return "", fail(off, "UTF-16 string of %d units runs past the pool", length)
	}
	units := make([]uint16, length)
	for i := range units {
		units[i], _ = r.u16(off + 2*i)
	}
	return string(utf16.Decode(units)), nil
}

// utf8String reads a UTF-8 pool string: its length in UTF-16 units, then
// its length in bytes (each one byte, or two if the top bit is set), then
// the bytes. Only the byte length is needed to read it.
func (r reader) utf8String(off, limit int) (string, error) {
	readLen := func() (int, error) {
		if off >= len(r.data) {
			return 0, fail(off, "read past end of data")
		}
		b := int(r.data[off])
		off++
		if b&0x80 == 0 {
			return b, nil
		}
		if off >= len(r.data) {
			return 0, fail(off, "read past end of data")
		}
		b = (b&0x7F)<<8 | int(r.data[off])
		off++
		return b, nil
	}
	if _, err := readLen(); err != nil { // length in UTF-16 units: not needed
		return "", err
	}
	n, err := readLen()
	if err != nil {
		return "", err
	}
	if off+n > limit {
		return "", fail(off, "UTF-8 string of %d bytes runs past the pool", n)
	}
	return string(r.data[off : off+n]), nil
}

func (r reader) startElement(c chunk, pool []string, resIDs []uint32, haveRes bool) (*Element, error) {
	str := func(idx uint32) (string, error) {
		if idx == noIndex {
			return "", nil
		}
		if int(idx) >= len(pool) {
			return "", fail(c.start, "string index %d out of range (%d strings)", idx, len(pool))
		}
		return pool[idx], nil
	}

	// After the 16-byte node header: ns, name, then the attribute layout.
	b := c.start + 16
	nameIdx, err := r.u32(b + 4)
	if err != nil {
		return nil, err
	}
	attrStart, err := r.u16(b + 8)
	if err != nil {
		return nil, err
	}
	attrSize, err := r.u16(b + 10)
	if err != nil {
		return nil, err
	}
	attrCount, err := r.u16(b + 12)
	if err != nil {
		return nil, err
	}
	name, err := str(nameIdx)
	if err != nil {
		return nil, err
	}
	if int(attrCount) > maxAttributes {
		return nil, fail(c.start, "element claims %d attributes", attrCount)
	}
	if attrCount > 0 && attrSize < 20 {
		return nil, fail(c.start, "attribute size %d is below the 20 bytes the format needs", attrSize)
	}

	el := &Element{Name: name, Attrs: make([]Attr, 0, attrCount)}
	first := b + int(attrStart)
	for i := 0; i < int(attrCount); i++ {
		a := first + i*int(attrSize)
		if a+20 > c.end {
			return nil, fail(a, "attribute %d runs past its element", i)
		}
		nsIdx, _ := r.u32(a)
		anameIdx, _ := r.u32(a + 4)
		rawIdx, _ := r.u32(a + 8)
		dataType := r.data[a+15]
		data, _ := r.u32(a + 16)

		ns, err := str(nsIdx)
		if err != nil {
			return nil, err
		}
		aname, err := str(anameIdx)
		if err != nil {
			return nil, err
		}
		raw, err := str(rawIdx)
		if err != nil {
			return nil, err
		}
		attr := Attr{Namespace: ns, Name: aname, DataType: dataType, Data: data, Raw: raw}
		if haveRes && int(anameIdx) < len(resIDs) {
			attr.ResourceID = resIDs[anameIdx]
		}
		el.Attrs = append(el.Attrs, attr)
	}
	return el, nil
}
