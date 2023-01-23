// A manual page generator for Go packages.
package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"unicode"
)

const (
	outputPathDefaultUsage = "~/.gman/<go-verion>/<package-name>.man"
)

func main() {
	log.SetFlags(0)

	err := mainWithError()
	if err != nil {
		log.Fatalln(err)
	}
}

func mainWithError() error {
	savePath := flag.String(
		"o",
		"",
		"The file path to save the manual to. "+
			"Specify '-' to indicate stdout (default: "+outputPathDefaultUsage)

	flag.Parse()

	if flag.NArg() == 0 {
		return errors.New("please specify one or more go package ids")
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

	// TODO: Allow this to be overriden via argument.
	version, err := goVersion(ctx)
	if err != nil {
		return err
	}

	for _, packageID := range flag.Args() {
		err = createOrReadManual(ctx, *savePath, packageID, version)
		if err != nil {
			return err
		}
	}

	return nil
}

func goVersion(ctx context.Context) (string, error) {
	stdoutRaw, err := exec.CommandContext(ctx, "go", "version").Output()
	if err != nil {
		return "", err
	}

	if len(stdoutRaw) == 0 {
		return "", errors.New("stdout of 'go version' is empty")
	}

	fields := strings.Fields(string(stdoutRaw))[1:]

	for _, field := range fields {
		if len(field) < 3 {
			continue
		}

		switch {
		case strings.HasPrefix(field, "go"):
			return field[2:], nil
		case unicode.IsNumber(rune(field[0])):
			return field, nil
		}
	}

	return "", fmt.Errorf("failed to find go version number in stdout - checked: '%s'", stdoutRaw)
}

func createOrReadManual(ctx context.Context, savePath string, packageID string, version string) error {
	if packageID == "." {
		return errors.New("'.' doc is not currently supported :(")
	}

	var writer io.Writer

	switch savePath {
	case "-":
		writer = os.Stdout
		savePath = os.Stdout.Name()
	default:
		if savePath == "" {
			homeDirPath, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			packageName := filepath.Base(packageID)

			savePath = filepath.Join(homeDirPath, ".gman", version, packageID, packageName+".man")
		}

		info, err := checkForExistingManual(savePath)
		if err != nil {
			return fmt.Errorf("failed to check if manual exists for '%s' - %w",
				packageID, err)
		}

		if info.Exists {
			man := exec.CommandContext(ctx, "man", savePath)
			man.Stdin = os.Stdin
			man.Stdout = os.Stdout
			man.Stderr = os.Stderr

			err = man.Run()
			if err != nil {
				return err
			}

			return nil
		}

		f, err := os.OpenFile(savePath, os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()

		writer = f
	}

	config := &packageManualConfig{
		PackageID: packageID,
		GoVersion: version,
		Writer:    writer,
	}

	err := config.genPackageManual(ctx)
	if err != nil {
		return fmt.Errorf("failed to generate package manual for '%s' - %w",
			packageID, err)
	}

	man := exec.CommandContext(ctx, "man", savePath)
	man.Stdin = os.Stdin
	man.Stdout = os.Stdout
	man.Stderr = os.Stderr

	err = man.Run()
	if err != nil {
		return err
	}

	return nil
}

func checkForExistingManual(fullPath string) (*manualInfo, error) {
	parentPath := filepath.Dir(fullPath)

	info, err := os.Stat(fullPath)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}

		err = os.MkdirAll(parentPath, 0o700)
		if err != nil {
			return nil, err
		}
	}

	return &manualInfo{
		ParentDirPath: parentPath,
		FilePath:      fullPath,
		Exists:        info != nil,
	}, nil

}

type manualInfo struct {
	ParentDirPath string
	FilePath      string
	Exists        bool
}

type packageManualConfig struct {
	PackageID string
	GoVersion string
	Writer    io.Writer
}

func (o *packageManualConfig) genPackageManual(ctx context.Context) error {
	goDoc := exec.CommandContext(ctx, "go", "doc", "-all", o.PackageID)
	stderr := bytes.NewBuffer(nil)
	goDoc.Stderr = stderr

	stdout, err := goDoc.Output()
	if err != nil {
		return fmt.Errorf("failed to execute '%s' - stderr: '%s' - %w",
			goDoc.Args, stderr.String(), err)
	}

	p := &parser{
		Scanner: bufio.NewScanner(bytes.NewReader(stdout)),
		Writer:  o.Writer,
	}

	err = o.packageInfo(p)
	if err != nil {
		return fmt.Errorf("failed to get go package info - %w", err)
	}

	// Write current token.
	if p.CurrentSection != "" {
		_, err = p.Writer.Write([]byte(".SH " + p.CurrentSection + "\n"))
		if err != nil {
			return err
		}
	}

	styler := &definitionStyler{}

	for p.Next(styler.styleize, nil) {
		_, err = p.Writer.Write([]byte(".SH " + p.CurrentSection + "\n"))
		if err != nil {
			return err
		}
	}

	return p.Err()
}

func (o *packageManualConfig) packageInfo(p *parser) error {
	// .TH foo 3 "" "version 1.0"
	_, err := p.Writer.Write([]byte(`.TH ` + o.PackageID + ` 3 "" "go ` + o.GoVersion + `"` + "\n"))
	if err != nil {
		return err
	}

	_, err = p.Writer.Write([]byte(".SH NAME\n"))
	if err != nil {
		return err
	}

	if !p.Next(nil, isEmptyLine) {
		return p.Err()
	}

	_, err = p.Writer.Write([]byte("\n.SH SYNOPSIS\n"))
	if err != nil {
		return err
	}

	styler := &introStyler{}

	if !p.Next(styler.styleize, nil) {
		return p.Err()
	}

	return nil
}

func isEmptyLine(line string) bool {
	return len(strings.TrimSpace(line)) == 0
}

type parser struct {
	CurrentSection string
	Scanner        *bufio.Scanner
	Writer         io.Writer
	err            error
}

func (o *parser) Err() error {
	return o.err
}

func (o *parser) Next(modLineFn func(string) string, stopAtFn func(string) bool) bool {
	for o.Scanner.Scan() {
		line := o.Scanner.Text()

		if isTitle(line) {
			o.CurrentSection = line

			_, o.err = o.Writer.Write([]byte{'\n'})
			if o.err != nil {
				return false
			}

			return true
		}

		if stopAtFn != nil && stopAtFn(line) {
			return true
		}

		if line == "" {
			_, o.err = o.Writer.Write([]byte{'\n'})
			if o.err != nil {
				return false
			}

			continue
		}

		if modLineFn != nil {
			line = modLineFn(line)
		}

		_, err := o.Writer.Write([]byte(line + "\n"))
		if err != nil {
			o.err = err
			return false
		}
	}

	o.err = o.Scanner.Err()

	return false
}

func isTitle(s string) bool {
	if len(s) == 0 {
		return false
	}

	for _, c := range s {
		r := rune(c)

		if !unicode.IsUpper(r) || unicode.IsSpace(r) {
			return false
		}
	}

	return true
}

type introStyler struct{}

func (o *introStyler) styleize(line string) string {
	if !isEmptyLine(line) {
		line = strings.ReplaceAll(line, "Deprecated: ", "\n.I Deprecated:\n")

		switch {
		case strings.HasPrefix(line, "# "):
			line = ".SH " + strings.ToUpper(line[2:])
		case strings.HasPrefix(line, "\x09"):
			line = ".sp 0\n" + line
		case unicode.IsUpper(rune(line[0])) && strings.HasSuffix(line, ":"):
			line = ".sp 0\n.B " + line
		}
	}

	return line
}

type definitionStyler struct{}

func (o *definitionStyler) styleize(line string) string {
	if !isEmptyLine(line) {
		line = strings.ReplaceAll(line, "Deprecated: ", "\n.I Deprecated:\n")

		switch {
		case strings.HasPrefix(line, "# "):
			line = ".SH " + strings.ToUpper(line[2:])
		case strings.HasPrefix(line, "\x09"):
			if strings.HasPrefix(strings.TrimSpace(line), "// ") {
				line = ".sp 0\n" + line
			} else {
				line = ".sp 0\n.B " + line
			}
		case !unicode.IsSpace(rune(line[0])):
			line = ".sp 0\n.B " + line
		}
	}

	return line
}
