package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// What apkwarden reports for three real apps, from F-Droid, pinned by
// SHA-256 (testdata/apks.sha256, which are the hashes F-Droid's index
// publishes). Run testdata/fetch-apks.sh and set APKWARDEN_APKS to enable.
//
// These are a regression record, not an oracle: the SDK levels and
// permissions underneath them are checked independently against F-Droid's
// index in internal/manifest, and for AntennaPod's backup and cleartext
// findings and KDE Connect's TransactionService finding the raw manifest
// attributes were read directly to confirm them.
var realExpected = map[string]struct {
	sha      string
	findings []string // "rule | location", in report order
}{
	"org.fdroid.fdroid_1023052.apk": {
		"985f5181d48bb6bafd54083a048b391271e0ab28385881cc41294fb01a222762",
		[]string{"target-sdk-below-floor | application"},
	},
	"de.danoeh.antennapod_3120095.apk": {
		"f5dde17e296d36453bfd5973361b7b07499edad2d93c205e2a4e770643af3a52",
		[]string{
			"exported-service-unprotected | service de.danoeh.antennapod.playback.service.Media3PlaybackService",
			"backup-allowed | application",
			"exported-receiver-unprotected | receiver androidx.media3.session.MediaButtonReceiver",
			"exported-receiver-unprotected | receiver de.danoeh.antennapod.net.download.service.feed.FeedUpdateReceiver",
			"exported-receiver-unprotected | receiver de.danoeh.antennapod.ui.widget.PlayerWidget",
			"cleartext-allowed | application",
		},
	},
	"org.kde.kdeconnect_tp_13515.apk": {
		"a3835741e0d037d7693d196acdf784817121aec647605b33b0dc69a8eac9247c",
		[]string{
			"exported-service-unprotected | service com.android.mms.transaction.TransactionService",
			"exported-receiver-unprotected | receiver org.kde.kdeconnect.plugins.findmyphone.FindMyPhoneReceiver",
			"exported-receiver-unprotected | receiver org.kde.kdeconnect.plugins.mpris.MprisMediaNotificationReceiver",
			"exported-receiver-unprotected | receiver org.kde.kdeconnect.plugins.runcommand.RunCommandWidgetProvider",
			"exported-receiver-unprotected | receiver org.kde.kdeconnect.plugins.share.ShareBroadcastReceiver",
		},
	},
}

func TestRealAPKFindings(t *testing.T) {
	dir := os.Getenv("APKWARDEN_APKS")
	if dir == "" {
		t.Skip("APKWARDEN_APKS not set; run testdata/fetch-apks.sh to enable the real-APK tests")
	}
	for file, want := range realExpected {
		path := filepath.Join(dir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if sum := sha256.Sum256(data); hex.EncodeToString(sum[:]) != want.sha {
			t.Fatalf("%s is not the file the expectations were written for (sha256 %x)", file, sum)
		}

		_, out, _ := exec("scan", "--format", "json", "--today", "2026-10-01", path)
		var doc struct {
			Findings []struct{ Rule, Location string }
		}
		if err := json.Unmarshal([]byte(out), &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		var got []string
		for _, f := range doc.Findings {
			got = append(got, f.Rule+" | "+f.Location)
		}
		if !reflect.DeepEqual(got, want.findings) {
			t.Errorf("%s:\n got  %s\n want %s", file, strings.Join(got, "\n      "), strings.Join(want.findings, "\n      "))
		}
	}
}

// The same three apps scanned through the terminal path must not crash and
// must give the exit codes the findings imply (high or above fails).
func TestRealAPKExitCodes(t *testing.T) {
	dir := os.Getenv("APKWARDEN_APKS")
	if dir == "" {
		t.Skip("APKWARDEN_APKS not set")
	}
	want := map[string]int{
		"org.fdroid.fdroid_1023052.apk":    0, // one medium finding
		"de.danoeh.antennapod_3120095.apk": 1, // an exported service
		"org.kde.kdeconnect_tp_13515.apk":  1,
	}
	for file, code := range want {
		if got, _, _ := exec("scan", filepath.Join(dir, file)); got != code {
			t.Errorf("%s: exit %d, want %d", file, got, code)
		}
	}
}
