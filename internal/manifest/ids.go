package manifest

// attrIDTable holds the framework attribute IDs this tool reads. Each is
// confirmed two ways, which TestAttrIDsMatchAndroidSource and
// TestAttrIDsAgreeWithRealManifests check: against Android's own
// public-final.xml (frameworks/base/core/res/res/values), and, for the
// ones a release APK actually contains, against the (name, ID) pairs in
// real APKs from F-Droid.
var attrIDTable = map[string]uint32{
	"allowBackup":           0x01010280,
	"authorities":           0x01010018,
	"autoVerify":            0x010104ee,
	"dataExtractionRules":   0x0101063e,
	"debuggable":            0x0101000f,
	"enabled":               0x0101000e,
	"exported":              0x01010010,
	"fullBackupContent":     0x010104eb,
	"grantUriPermissions":   0x0101001b,
	"minSdkVersion":         0x0101020c,
	"name":                  0x01010003,
	"networkSecurityConfig": 0x01010527,
	"permission":            0x01010006,
	"protectionLevel":       0x01010009,
	"readPermission":        0x01010007,
	"scheme":                0x01010027,
	"sharedUserId":          0x0101000b,
	"targetSdkVersion":      0x01010270,
	"testOnly":              0x01010272,
	"usesCleartextTraffic":  0x010104ec,
	"writePermission":       0x01010008,
}
