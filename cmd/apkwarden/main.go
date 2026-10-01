// apkwarden reads an Android app's manifest and reports insecure settings.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/sriharifortitude/apkwarden/internal/apk"
	"github.com/sriharifortitude/apkwarden/internal/axml"
	"github.com/sriharifortitude/apkwarden/internal/manifest"
	"github.com/sriharifortitude/apkwarden/internal/report"
	"github.com/sriharifortitude/apkwarden/internal/rules"
	"github.com/sriharifortitude/apkwarden/internal/waiver"
)

const version = "0.1.0"

const usage = `usage:
  apkwarden scan [flags] <app.apk | AndroidManifest.xml>
  apkwarden rules

scan flags:
  --format terminal|json|sarif   output format (default terminal)
  --fail-on critical|high|medium|low   fail at or above this severity (default high)
  --waivers FILE                 accepted-risk waivers, each with a reason and an expiry
  --min-target-sdk N             lowest targetSdkVersion that is not flagged (default 34)
  --today YYYY-MM-DD             the date waivers are judged against (default: today)

exit codes: 0 nothing failing at --fail-on, 1 something is, 2 the input could not be read`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "rules":
		for _, r := range rules.All() {
			fmt.Fprintf(stdout, "%-30s %-8s %s\n", r.ID(), r.Severity(), r.Description())
		}
		return 0
	case "scan":
		return scan(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "-V", "--version", "version":
		fmt.Fprintln(stdout, "apkwarden", version)
		return 0
	}
	fmt.Fprintf(stderr, "apkwarden: unknown command %q\n\n%s\n", args[0], usage)
	return 2
}

func scan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	format := fs.String("format", "terminal", "")
	failOn := fs.String("fail-on", "high", "")
	waiversPath := fs.String("waivers", "", "")
	minTarget := fs.Int("min-target-sdk", rules.DefaultConfig().MinTargetSDK, "")
	todayFlag := fs.String("today", "", "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "apkwarden: %v\n\n%s\n", err, usage)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "apkwarden: scan takes exactly one file\n\n%s\n", usage)
		return 2
	}
	threshold, ok := rules.ParseSeverity(*failOn)
	if !ok {
		fmt.Fprintf(stderr, "apkwarden: --fail-on %q: use critical, high, medium or low\n", *failOn)
		return 2
	}
	if *format != "terminal" && *format != "json" && *format != "sarif" {
		fmt.Fprintf(stderr, "apkwarden: --format %q: use terminal, json or sarif\n", *format)
		return 2
	}
	today := time.Now()
	if *todayFlag != "" {
		t, err := time.Parse("2006-01-02", *todayFlag)
		if err != nil {
			fmt.Fprintf(stderr, "apkwarden: --today %q is not YYYY-MM-DD\n", *todayFlag)
			return 2
		}
		today = t
	}

	var waivers *waiver.File
	if *waiversPath != "" {
		data, err := os.ReadFile(*waiversPath)
		if err != nil {
			fmt.Fprintf(stderr, "apkwarden: %v\n", err)
			return 2
		}
		if waivers, err = waiver.Parse(data); err != nil {
			fmt.Fprintf(stderr, "apkwarden: %s: %v\n", *waiversPath, err)
			return 2
		}
	}

	input := fs.Arg(0)
	m, err := load(input)
	if err != nil {
		fmt.Fprintf(stderr, "apkwarden: %s: %v\n", input, err)
		return 2
	}

	findings := rules.RunAll(m, rules.Config{MinTargetSDK: *minTarget})
	run := &report.Run{
		Input: input, Manifest: m, FailOn: threshold, Today: today, Rules: rules.All(),
		Items: report.Build(findings, waivers, today), Unused: waivers.Unused(findings),
		ToolName: "apkwarden", ToolVer: version, ToolURL: "https://github.com/sriharifortitude/apkwarden",
	}

	switch *format {
	case "json":
		b, err := run.JSON()
		if err != nil {
			fmt.Fprintf(stderr, "apkwarden: %v\n", err)
			return 2
		}
		stdout.Write(b)
	case "sarif":
		b, err := run.SARIF()
		if err != nil {
			fmt.Fprintf(stderr, "apkwarden: %v\n", err)
			return 2
		}
		stdout.Write(b)
	default:
		io.WriteString(stdout, run.Terminal())
	}
	return run.ExitCode()
}

func load(path string) (*manifest.Manifest, error) {
	data, err := apk.ReadManifest(path)
	if err != nil {
		// The OS error already repeats the path and words its reason
		// differently per platform; say it once, the same way everywhere.
		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, errors.New("no such file")
		case errors.Is(err, fs.ErrPermission):
			return nil, errors.New("permission denied")
		}
		var pe *fs.PathError
		if errors.As(err, &pe) {
			return nil, pe.Err
		}
		return nil, err
	}
	doc, err := axml.Parse(data)
	if err != nil {
		if errors.Is(err, axml.ErrNotAXML) {
			return nil, errors.New(notAXMLHint(data))
		}
		return nil, err
	}
	return manifest.Parse(doc)
}

// notAXMLHint explains the most common wrong input: an AndroidManifest.xml
// from a source tree, which is plain text, not the compiled form inside an APK.
func notAXMLHint(data []byte) string {
	if strings.HasPrefix(strings.TrimSpace(string(data[:min(len(data), 64)])), "<") {
		return "this is a plain-text manifest, from a source tree. apkwarden reads the compiled one inside a built APK (a source manifest is missing what the build merges in from libraries, so it would be misleading to scan)"
	}
	return "not an APK (zip) or a compiled AndroidManifest.xml"
}
