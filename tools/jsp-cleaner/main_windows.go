//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const version = "1.0.1"

type options struct {
	dir      string
	logFile  string
	interval time.Duration
	dryRun   bool
	once     bool
}

type scanStats struct {
	Files, Matched, Deleted, Skipped, Errors int
}

type cleaner struct {
	root    *os.Root
	path    string
	dryRun  bool
	log     *slog.Logger
	lastErr map[string]string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var opt options
	flags := flag.NewFlagSet("jsp-cleaner", flag.ContinueOnError)
	flags.StringVar(&opt.dir, "dir", "", "absolute local directory to scan recursively")
	flags.StringVar(&opt.logFile, "log", filepath.Join(filepath.Dir(exe), "jsp-cleaner.log"), "JSONL audit log; must be outside the target")
	flags.DurationVar(&opt.interval, "interval", time.Second, "delay between completed scans, minimum 10ms")
	flags.BoolVar(&opt.dryRun, "dry-run", true, "report matches without deleting files")
	flags.BoolVar(&opt.once, "once", false, "scan once and exit")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Println("jsp-cleaner", version, runtime.Version(), runtime.GOARCH)
		return 0
	}
	if flags.NArg() != 0 || opt.interval < 10*time.Millisecond {
		fmt.Fprintln(os.Stderr, "Unexpected argument or interval shorter than 10ms.")
		return 2
	}
	target, err := validateTarget(opt.dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid target:", err)
		return 2
	}
	logPath, err := filepath.Abs(opt.logFile)
	if err != nil || strings.EqualFold(logPath, target) || isWithin(target, logPath) {
		fmt.Fprintln(os.Stderr, "The audit log must be outside the target directory.")
		return 2
	}
	root, err := os.OpenRoot(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open target:", err)
		return 1
	}
	defer root.Close()
	if err := checkRoot(root, target); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot verify target:", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(logPath), 0700); err != nil {
		fmt.Fprintln(os.Stderr, "Cannot create log directory:", err)
		return 1
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Cannot open audit log:", err)
		return 1
	}
	defer logFile.Close()
	logger := slog.New(slog.NewJSONHandler(io.MultiWriter(os.Stdout, logFile), nil))
	c := &cleaner{root: root, path: target, dryRun: opt.dryRun, log: logger, lastErr: make(map[string]string)}
	logger.Info("started", "version", version, "target", target, "extensions", ".jsp,.jspx,.jspf",
		"interval", opt.interval.String(), "dry_run", opt.dryRun, "once", opt.once,
		"deletion", "permanent; not the recycle bin")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	exitCode := 0
	lastHeartbeat := time.Now()
	for {
		stats, err := c.scan(ctx)
		if errors.Is(err, context.Canceled) {
			break
		}
		if err != nil {
			logger.Error("scan_stopped", "error", err)
			exitCode = 1
			break
		}
		if stats.Matched > 0 || stats.Errors > 0 || time.Since(lastHeartbeat) >= time.Minute || opt.once {
			logger.Info("scan_finished", "files", stats.Files, "matched", stats.Matched,
				"deleted", stats.Deleted, "skipped_reparse_or_special", stats.Skipped, "errors", stats.Errors)
			lastHeartbeat = time.Now()
		}
		if err := logFile.Sync(); err != nil {
			fmt.Fprintln(os.Stderr, "Audit log sync failed; stopping:", err)
			exitCode = 1
			break
		}
		if opt.once {
			if stats.Errors > 0 {
				exitCode = 1
			}
			break
		}
		timer := time.NewTimer(opt.interval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		if ctx.Err() != nil {
			break
		}
	}
	logger.Info("stopped", "exit_code", exitCode)
	_ = logFile.Sync()
	return exitCode
}

func (c *cleaner) scan(ctx context.Context) (scanStats, error) {
	var stats scanStats
	if err := checkRoot(c.root, c.path); err != nil {
		return stats, err
	}
	currentErrors := make(map[string]string)
	defer func() { c.lastErr = currentErrors }()
	reportError := func(name string, err error) {
		c.reportError(name, err)
		currentErrors[name] = err.Error()
	}
	// Root.FS and Root.Remove bind operations to the opened directory and
	// reject traversal outside it, including symlink replacement races.
	err := fs.WalkDir(c.root.FS(), ".", func(name string, d fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if errors.Is(walkErr, fs.ErrNotExist) {
				return nil
			}
			stats.Errors++
			reportError(name, walkErr)
			if name == "." {
				return walkErr
			}
			return nil
		}
		// Windows junctions can be ModeIrregular rather than ModeSymlink.
		// Never descend into any non-plain directory entry.
		if d.Type() != 0 && d.Type() != fs.ModeDir {
			stats.Skipped++
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && !matchesJSP(d.Name()) {
			stats.Files++
			return nil
		}
		info, err := c.root.Lstat(filepath.FromSlash(name))
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				stats.Errors++
				reportError(name, err)
			}
			return nil
		}
		if isReparse(info) {
			stats.Skipped++
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			stats.Skipped++
			return nil
		}
		stats.Files++
		if !matchesJSP(info.Name()) {
			return nil
		}
		stats.Matched++
		display := filepath.Join(c.path, filepath.FromSlash(name))
		if c.dryRun {
			c.log.Info("would_delete", "path", display, "bytes", info.Size(), "modified", info.ModTime())
			return nil
		}
		if err := c.root.Remove(filepath.FromSlash(name)); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				stats.Errors++
				reportError(name, err)
			}
			return nil
		}
		delete(c.lastErr, name)
		stats.Deleted++
		c.log.Info("deleted", "path", display, "bytes_before_delete", info.Size(), "modified_before_delete", info.ModTime())
		return nil
	})
	return stats, err
}

func (c *cleaner) reportError(name string, err error) {
	// Retry on every scan, but avoid logging an identical locked-file error
	// every second. The per-scan error count remains visible.
	message := err.Error()
	if c.lastErr[name] != message {
		c.log.Error("file_error", "path", filepath.Join(c.path, filepath.FromSlash(name)), "error", message, "retry", "next scan")
		c.lastErr[name] = message
	}
}

func matchesJSP(name string) bool {
	ext := strings.ToLower(filepath.Ext(strings.TrimRight(name, " .")))
	return ext == ".jsp" || ext == ".jspx" || ext == ".jspf"
}

func isWithin(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != "." && filepath.IsLocal(rel)
}

func isReparse(info fs.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}

func validateTarget(path string) (string, error) {
	path = filepath.Clean(path)
	volume := filepath.VolumeName(path)
	if !filepath.IsAbs(path) || len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("use an absolute local drive path, for example D:/upload-storage")
	}
	if strings.EqualFold(path, volume+string(os.PathSeparator)) {
		return "", errors.New("refusing a drive root")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return "", err
		}
		if !info.IsDir() || isReparse(info) {
			return "", fmt.Errorf("directory or ancestor is not a plain directory: %s", current)
		}
		if current == filepath.Dir(current) {
			break
		}
	}
	return path, nil
}

var getFinalPath = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

func checkRoot(root *os.Root, expected string) error {
	f, err := root.Open(".")
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]uint16, 512)
	for {
		n, _, callErr := getFinalPath.Call(f.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		runtime.KeepAlive(f)
		if n == 0 {
			return fmt.Errorf("GetFinalPathNameByHandleW: %w", callErr)
		}
		if n >= uintptr(len(buf)) {
			if n > 32768 {
				return errors.New("unexpected final path length")
			}
			buf = make([]uint16, int(n)+1)
			continue
		}
		actual := filepath.Clean(strings.TrimPrefix(syscall.UTF16ToString(buf[:n]), "\\\\?\\"))
		if !strings.EqualFold(actual, expected) {
			return fmt.Errorf("root path changed or resolves elsewhere: expected %s, got %s", expected, actual)
		}
		return nil
	}
}
