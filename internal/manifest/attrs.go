package manifest

import (
	"strconv"

	"github.com/sriharifortitude/apkwarden/internal/axml"
)

// AttrIDs returns a copy of the framework attribute ID table, for tests
// that check it against Android's own sources.
func AttrIDs() map[string]uint32 {
	out := make(map[string]uint32, len(attrIDTable))
	for k, v := range attrIDTable {
		out[k] = v
	}
	return out
}

// Compiled XML stores an attribute's name as a string, but obfuscation
// tools blank those strings and the runtime still works, because it looks
// attributes up by ID. So an attribute is matched by name first, and by ID
// when the name is empty (see ids.go).
//
// get finds an android-namespace attribute on el.
func get(el *axml.Element, name string) (axml.Attr, bool) {
	id := attrIDTable[name]
	for _, a := range el.Attrs {
		if !a.IsAndroid() {
			continue
		}
		if a.Name == name || (a.Name == "" && id != 0 && a.ResourceID == id) {
			return a, true
		}
	}
	return axml.Attr{}, false
}

// str returns an attribute's string value, or "" if absent or not a string.
func str(el *axml.Element, name string) string {
	a, ok := get(el, name)
	if !ok || a.DataType != axml.TypeString {
		return ""
	}
	return a.Raw
}

func boolAttr(el *axml.Element, name string) Tri {
	a, ok := get(el, name)
	if !ok {
		return Unset
	}
	switch a.DataType {
	case axml.TypeBoolean:
		if a.Data != 0 {
			return True
		}
		return False
	case axml.TypeString:
		// Very old toolchains wrote the text. Anything but exactly true or
		// false is a value Android itself would reject.
		switch a.Raw {
		case "true":
			return True
		case "false":
			return False
		}
	}
	return Unknown
}

// intAttr reads an integer attribute. 0 means absent; SDKUnknown means
// present but not a plain integer.
func intAttr(el *axml.Element, name string) int {
	a, ok := get(el, name)
	if !ok {
		return 0
	}
	switch a.DataType {
	case axml.TypeIntDec, axml.TypeIntHex:
		return int(int32(a.Data))
	case axml.TypeString:
		if n, err := strconv.Atoi(a.Raw); err == nil {
			return n
		}
	}
	return SDKUnknown
}
