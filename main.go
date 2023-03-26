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
	"runtime"
	"strings"
	"unicode"
)

const (
	appName = "gman"

	usage = appName + `

SYNOPSIS
  ` + appName + ` [options] <go-package-id>

DESCRIPTION
  A manual page generator for Go packages.

EXAMPLES
  Generate and view the "crypto/tls" library manual:
    $ ` + appName + ` crypto/tls

  Generate and view the manual for "golang.org/x/sys/unix" for FreeBSD:
    $ ` + appName + ` -` + goOSArg + ` freebsd golang.org/x/sys/unix

  Generate and view the manual for v0.4.0 of "golang.org/x/crypto/ssh":
    $ ` + appName + ` golang.org/x/crypto/ssh@v0.4.0

  Generate the manual for the "syscall" library for OpenBSD and exit:
    $ ` + appName + ` -` + genOnlyArg + ` -` + goOSArg + ` openbsd bytes

OPTIONS
`

	helpArg     = "h"
	savePathArg = "o"
	goOSArg     = "s"
	goArchArg   = "a"
	genOnlyArg  = "G"
	regenArg    = "F"

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
	help := flag.Bool(
		helpArg,
		false,
		"Display this information")
	genOnly := flag.Bool(
		genOnlyArg,
		false,
		"Generate the manual page and exit")
	regen := flag.Bool(
		regenArg,
		false,
		"Regenerate the manual page even if one already exists")
	savePath := flag.String(
		savePathArg,
		"",
		"The file path to save the manual to. "+
			"Specify '-' to use stdout\n(default: "+
			outputPathDefaultUsage+")")
	goOS := flag.String(
		goOSArg,
		goBuildEnvOrRuntime("GOOS"),
		"The GOOS (target operating system) to lookup (defaults to\n"+
			"GOOS env value or runtime.GOOS)")
	goArch := flag.String(
		goArchArg,
		goBuildEnvOrRuntime("GOARCH"),
		"The GOARCH (target CPU) to lookup (defaults to GOARCH env\n"+
			"value or runtime.GOARCH)")

	flag.Parse()

	if *help {
		_, _ = os.Stderr.WriteString(usage)
		flag.PrintDefaults()
		os.Exit(1)
	}

	if flag.NArg() == 0 {
		return errors.New("please specify one or more go package ids")
	}

	ctx, cancelFn := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancelFn()

	// TODO: Allow this to be overriden via argument.
	goVer, err := goVersion(ctx)
	if err != nil {
		return err
	}

	for _, packageID := range flag.Args() {
		err = createOrReadManual(ctx, createOrReadManualConfig{
			genOnly:   *genOnly,
			regen:     *regen,
			savePath:  *savePath,
			goOS:      *goOS,
			goArch:    *goArch,
			packageID: packageID,
			goVersion: goVer,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func goBuildEnvOrRuntime(envName string) string {
	value := os.Getenv(envName)
	if value != "" {
		return value
	}

	switch envName {
	case "GOOS":
		return runtime.GOOS
	case "GOARCH":
		return runtime.GOARCH
	default:
		return ""
	}
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

type createOrReadManualConfig struct {
	genOnly   bool
	regen     bool
	savePath  string
	goOS      string
	goArch    string
	packageID string
	goVersion string
}

func createOrReadManual(ctx context.Context, config createOrReadManualConfig) error {
	if config.packageID == "." {
		return errors.New("'.' doc is not currently supported :(")
	}

	info, err := extractPackageInfo(config.packageID, config.goOS, config.goArch)
	if err != nil {
		return err
	}

	var writer io.WriteCloser

	switch config.savePath {
	case "-":
		writer = os.Stdout
		config.savePath = os.Stdout.Name()
	default:
		if config.savePath == "" {
			homeDirPath, err := os.UserHomeDir()
			if err != nil {
				return err
			}

			manualFileName := filepath.Base(info.Name)
			if info.IsStdLib {
				manualFileName = manualFileName + "-" + config.goVersion
			} else if info.Version != "" {
				manualFileName = manualFileName + "-" + info.Version
			}

			config.savePath = filepath.Join(
				homeDirPath,
				".gman",
				config.goOS,
				config.goArch,
				info.Name,
				manualFileName+".man")
		}

		info, err := checkForExistingManual(config.savePath)
		if err != nil {
			return fmt.Errorf("failed to check if manual exists for '%s' - %w",
				config.packageID, err)
		}

		if !config.regen && info.Exists {
			if config.genOnly {
				return nil
			}

			man := exec.CommandContext(ctx, "man", config.savePath)
			man.Stdin = os.Stdin
			man.Stdout = os.Stdout
			man.Stderr = os.Stderr

			err = man.Run()
			if err != nil {
				return err
			}

			return nil
		}

		fileFlags := os.O_CREATE | os.O_WRONLY
		if config.regen {
			fileFlags |= os.O_TRUNC
		}

		f, err := os.OpenFile(config.savePath, fileFlags, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()

		writer = f
	}

	genConfig := &packageManualConfig{
		Info:   info,
		GoVer:  config.goVersion,
		Writer: writer,
	}

	err = genConfig.genPackageManual(ctx)
	if err != nil {
		if writer != os.Stdout {
			// Remove empty file.
			_ = writer.Close()
			_ = os.Remove(config.savePath)
		}

		return fmt.Errorf("failed to generate package manual for '%s' - %w",
			config.packageID, err)
	}

	if config.genOnly {
		return nil
	}

	man := exec.CommandContext(ctx, "man", config.savePath)
	man.Stdin = os.Stdin
	man.Stdout = os.Stdout
	man.Stderr = os.Stderr

	err = man.Run()
	if err != nil {
		return err
	}

	return nil
}

func extractPackageInfo(packageID string, goOS string, goArch string) (*PackageInfo, error) {
	if strings.Contains(packageID, "..") {
		return nil, errors.New("package id contains '..'")
	}

	name := packageID
	isStdLib := true
	var version string

	before, after, hasVersion := strings.Cut(packageID, "@")
	if hasVersion {
		version = after
		name = before
		isStdLib = false
	}

	if isStdLib && strings.Contains(packageID, ".") {
		isStdLib = false
	}

	return &PackageInfo{
		ID:       packageID,
		Name:     name,
		Version:  version,
		IsStdLib: isStdLib,
		GoOS:     goOS,
		GoArch:   goArch,
	}, nil
}

type PackageInfo struct {
	// ID is the package's ID (e.g., "crypto/tls"
	// or "golang.org/x/sys/unix@vX.Y.Z").
	ID string

	// Name is the package's name (e.g., "crypto/tls"
	// or "golang.org/x/sys/unix" - basically, the ID
	// without the version).
	Name string

	// Version is the package's version - if any.
	Version string

	// IsStdLib is true if the package is part of the Go
	// standard library.
	IsStdLib bool

	// GoOS is the GOOS value used when generating
	// the documentation.
	GoOS string

	// GoArch is the GOARCH value used when generating
	// the documentation.
	GoArch string
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
	Info   *PackageInfo
	GoVer  string
	Writer io.Writer
}

func (o *packageManualConfig) genPackageManual(ctx context.Context) error {
	stdout, needsGet, err := goDocPackage(ctx, "", o.Info)
	if needsGet {
		var tmpDirPath string
		tmpDirPath, err = goGetPackage(ctx, o.Info)
		if err != nil {
			return fmt.Errorf("failed to 'go get' package - %w", err)
		}

		stdout, _, err = goDocPackage(ctx, tmpDirPath, o.Info)
		if err != nil {
			return fmt.Errorf("failed to 'go doc' package after getting it - %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to 'go doc' package - %w", err)
	}

	p := &parser{
		Scanner: bufio.NewScanner(bytes.NewReader(stdout)),
		Writer:  o.Writer,
	}

	err = o.packageInfo(p)
	if err != nil {
		return fmt.Errorf("failed to generate go package manual info - %w", err)
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

func goDocPackage(ctx context.Context, cwd string, info *PackageInfo) ([]byte, bool, error) {
	goDoc := exec.CommandContext(ctx, "go", "doc", "-all", info.Name)
	goDoc.Env = replaceGoEnvsIn(info.GoOS, info.GoArch, os.Environ())
	goDoc.Dir = cwd

	stderr := bytes.NewBuffer(nil)
	goDoc.Stderr = stderr

	stdout, err := goDoc.Output()
	if err != nil {
		needsGet := strings.HasPrefix(
			stderr.String(),
			"doc: no required module provides package "+info.Name)

		return nil, needsGet, fmt.Errorf("failed to execute '%s' - stderr: '%s' - %w",
			goDoc.Args, stderr.String(), err)
	}

	return stdout, false, nil
}

func goGetPackage(ctx context.Context, info *PackageInfo) (string, error) {
	tempDirPath, err := os.MkdirTemp("", "")
	if err != nil {
		return "", err
	}

	err = os.WriteFile(filepath.Join(tempDirPath, "go.mod"), []byte("module temp\n"), 0o600)
	if err != nil {
		return "", err
	}

	goGet := exec.CommandContext(ctx, "go", "get", info.ID)
	goGet.Dir = tempDirPath

	out, err := goGet.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute '%s' - %w - output: '%s'",
			goGet.String(), err, out)
	}

	return tempDirPath, nil
}

func (o *packageManualConfig) packageInfo(p *parser) error {
	version := o.Info.Version
	if o.Info.IsStdLib {
		version = o.GoVer
	}

	// .TH foo 3 "" "version 1.0"
	_, err := p.Writer.Write([]byte(`.TH ` + o.Info.ID + ` 3 "" "go ` + version + `"` + "\n"))
	if err != nil {
		return err
	}

	_, err = p.Writer.Write([]byte(".SH PLATFORM\n"))
	if err != nil {
		return err
	}

	_, err = p.Writer.Write([]byte(o.Info.GoOS + " " + o.Info.GoArch + "\n"))
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

func replaceGoEnvsIn(goOS string, goArch string, env []string) []string {
	foundOS := false
	foundArch := false

	for i, keyValue := range env {
		before, _, _ := strings.Cut(keyValue, "=")
		switch before {
		case "GOOS":
			env[i] = "GOOS=" + goOS
			foundOS = true
		case "GOARCH":
			env[i] = "GOARCH=" + goArch
			foundArch = true
		}
	}

	if !foundOS {
		env = append(env, "GOOS="+goOS)
	}

	if !foundArch {
		env = append(env, "GOARCH="+goArch)
	}

	return env
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
