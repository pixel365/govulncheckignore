package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const defaultIgnoreFile = ".govulncheckignore"

var (
	version     = "dev"
	commit      = "unknown"
	releaseDate = "unknown"
)

type ignoreFlags []string

func (f *ignoreFlags) String() string {
	return strings.Join(*f, ", ")
}

func (f *ignoreFlags) Set(value string) error {
	value = normalizeID(value)
	if value == "" {
		return errors.New("empty vulnerability ID")
	}

	*f = append(*f, value)
	return nil
}

func normalizeID(id string) string {
	return strings.ToUpper(strings.TrimSpace(id))
}

type config struct {
	ProtocolVersion string `json:"protocol_version"`
	ScanLevel       string `json:"scan_level"`
	ScanMode        string `json:"scan_mode"`
}

type osv struct {
	ID      string   `json:"id"`
	Aliases []string `json:"aliases"`
}

type frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

type finding struct {
	OSV   string  `json:"osv"`
	Trace []frame `json:"trace"`
}

type message struct {
	Config  *config  `json:"config,omitempty"`
	OSV     *osv     `json:"osv,omitempty"`
	Finding *finding `json:"finding,omitempty"`
}

type findingLevel int

const (
	levelModule findingLevel = iota + 1
	levelPackage
	levelCalled
)

func (l findingLevel) String() string {
	switch l {
	case levelModule:
		return "module"
	case levelPackage:
		return "package"
	case levelCalled:
		return "called"
	default:
		return "unknown"
	}
}

type exitError struct{}

func (exitError) Error() string {
	return "unignored reachable vulnerabilities found"
}

func main() {
	var ignored ignoreFlags
	var ignoreFile string
	var showVersion bool

	flag.BoolVar(
		&showVersion,
		"version",
		false,
		"Print version information and exit",
	)

	flag.Var(
		&ignored,
		"ignore",
		"CVE or GO vulnerability ID to ignore (repeatable)",
	)

	flag.StringVar(
		&ignoreFile,
		"ignore-file",
		"",
		"Path to ignore file (default: .govulncheckignore if present)",
	)

	flag.Parse()

	if flag.NArg() != 0 {
		fmt.Fprintln(
			os.Stderr,
			"govulncheckignore: unexpected positional arguments",
		)
		os.Exit(2)
	}

	if showVersion {
		fmt.Printf(
			"govulncheckignore %s (commit: %s, built: %s)\n",
			version,
			commit,
			releaseDate,
		)
		return
	}

	if ignoreFile == "" {
		ignoreFile = defaultIgnoreFile

		if _, err := os.Stat(ignoreFile); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				ignoreFile = ""
			} else {
				fmt.Fprintln(
					os.Stderr,
					"govulncheckignore:",
					err,
				)
				os.Exit(2)
			}
		}
	}

	if ignoreFile != "" {
		ids, err := readIgnoreFile(ignoreFile)
		if err != nil {
			fmt.Fprintln(
				os.Stderr,
				"govulncheckignore:",
				err,
			)
			os.Exit(2)
		}

		ignored = append(ignored, ids...)
	}

	if err := run(os.Stdin, os.Stdout, ignored); err != nil {
		if _, ok := errors.AsType[exitError](err); ok {
			os.Exit(1)
		}

		fmt.Fprintln(
			os.Stderr,
			"govulncheckignore:",
			err,
		)
		os.Exit(2)
	}
}

func readIgnoreFile(path string) ([]string, error) {
	path = filepath.Clean(path)

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf(
			"open ignore file %q: %w",
			path,
			err,
		)
	}
	defer func() {
		_ = file.Close()
	}()

	var ids []string

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if index := strings.IndexByte(line, '#'); index >= 0 {
			line = line[:index]
		}

		id := normalizeID(line)
		if id == "" {
			continue
		}

		ids = append(ids, id)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf(
			"read ignore file %q: %w",
			path,
			err,
		)
	}

	return ids, nil
}

func run(r io.Reader, w io.Writer, ignored []string) error {
	decoder := json.NewDecoder(r)

	aliases := make(map[string][]string)
	findings := make(map[string]findingLevel)
	ignoreSet := make(map[string]bool)

	for _, id := range ignored {
		ignoreSet[normalizeID(id)] = true
	}

	var cfg *config

	for {
		var msg message

		err := decoder.Decode(&msg)

		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			return fmt.Errorf(
				"decode JSON at byte offset %d: %w",
				decoder.InputOffset(),
				err,
			)
		}

		if msg.Config != nil {
			cfg = msg.Config
		}

		if msg.OSV != nil {
			id := normalizeID(msg.OSV.ID)

			if id == "" {
				return errors.New(
					"invalid OSV entry: missing ID",
				)
			}

			aliases[id] = msg.OSV.Aliases
		}

		if msg.Finding != nil {
			id := normalizeID(msg.Finding.OSV)

			if id == "" {
				return errors.New(
					"invalid finding: missing OSV ID",
				)
			}

			level := classifyFinding(msg.Finding)

			if level > findings[id] {
				findings[id] = level
			}
		}
	}

	if cfg == nil {
		return errors.New(
			"invalid govulncheck stream: missing config",
		)
	}

	if cfg.ProtocolVersion != "v1.0.0" {
		return fmt.Errorf(
			"unsupported protocol version: %q",
			cfg.ProtocolVersion,
		)
	}

	if cfg.ScanMode != "source" ||
		cfg.ScanLevel != "symbol" {
		return fmt.Errorf(
			"unsupported scan mode/level: %s/%s (expected source/symbol)",
			cfg.ScanMode,
			cfg.ScanLevel,
		)
	}

	for id := range findings {
		if _, ok := aliases[id]; !ok {
			return fmt.Errorf(
				"missing OSV entry for finding %q",
				id,
			)
		}
	}

	var skipped []string
	var remaining []string
	var informational []string

	for id, level := range findings {
		ignore := ignoreSet[id]

		for _, alias := range aliases[id] {
			if ignoreSet[normalizeID(alias)] {
				ignore = true
				break
			}
		}

		switch {
		case ignore:
			skipped = append(skipped, id)

		case level == levelCalled:
			remaining = append(remaining, id)

		default:
			informational = append(informational, id)
		}
	}

	sort.Strings(skipped)
	sort.Strings(remaining)
	sort.Strings(informational)

	for _, id := range skipped {
		if _, err := fmt.Fprintf(
			w,
			"SKIPPED  %s\n",
			id,
		); err != nil {
			return err
		}
	}

	for _, id := range remaining {
		if _, err := fmt.Fprintf(
			w,
			"FOUND    %s (called)\n",
			id,
		); err != nil {
			return err
		}
	}

	for _, id := range informational {
		if _, err := fmt.Fprintf(
			w,
			"INFO     %s (%s)\n",
			id,
			findings[id],
		); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprintf(
		w,
		"\nSummary: %d found, %d ignored, %d informational\n",
		len(remaining),
		len(skipped),
		len(informational),
	); err != nil {
		return err
	}

	if len(remaining) > 0 {
		return exitError{}
	}

	return nil
}

func classifyFinding(f *finding) findingLevel {
	if len(f.Trace) == 0 {
		return levelModule
	}

	first := f.Trace[0]

	switch {
	case first.Function != "":
		return levelCalled
	case first.Package != "":
		return levelPackage
	default:
		return levelModule
	}
}
