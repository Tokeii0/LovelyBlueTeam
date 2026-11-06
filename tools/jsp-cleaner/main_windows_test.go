//go:build windows

package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func testCleaner(t *testing.T, path string, dry bool) *cleaner {
	t.Helper()
	canonical, err := validateTarget(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(canonical)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &cleaner{root: root, path: canonical, dryRun: dry,
		log: slog.New(slog.NewJSONHandler(io.Discard, nil)), lastErr: make(map[string]string)}
}

func putFile(t *testing.T, dir, name string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("benign test fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return p
}

func assertExists(t *testing.T, p string, want bool) {
	t.Helper()
	_, err := os.Lstat(p)
	if want && err != nil {
		t.Fatalf("expected preserved path %s: %v", p, err)
	}
	if !want && !os.IsNotExist(err) {
		t.Fatalf("expected removed path %s, got %v", p, err)
	}
}

func TestPublicCLIDefaultsPreserveFilesAndRequireExplicitDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "uploads")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	file := putFile(t, target, "synthetic.jsp")
	if code := run([]string{"-dir", target, "-once", "-log", filepath.Join(base, "audit.log")}); code != 0 {
		t.Fatalf("preview returned %d", code)
	}
	assertExists(t, file, true)
	if code := run(nil); code != 2 {
		t.Fatalf("missing directory must fail with exit 2, got %d", code)
	}
}

func TestRecursiveDeletionPreservesBusinessFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.jsp", "nested/B.JSP", "deep/c.JspX", "deep/d.jspf"} {
		putFile(t, dir, name)
	}
	keep := []string{"logo.png", "report.pdf", "WEB-INF/web.xml", "cache/ok.class", "a.jsp.bak", "notjsp", "notes.txt"}
	for _, name := range keep {
		putFile(t, dir, name)
	}
	if err := os.Mkdir(filepath.Join(dir, "keep.jsp"), 0700); err != nil {
		t.Fatal(err)
	}
	c := testCleaner(t, dir, false)
	stats, err := c.scan(context.Background())
	if err != nil || stats.Deleted != 4 || stats.Errors != 0 {
		t.Fatalf("stats=%+v err=%v", stats, err)
	}
	for _, name := range keep {
		assertExists(t, filepath.Join(dir, name), true)
	}
	assertExists(t, filepath.Join(dir, "keep.jsp"), true)
	assertExists(t, filepath.Join(dir, "nested/B.JSP"), false)
}

func TestDryRunAndLaterCreatedOrRenamedFiles(t *testing.T) {
	dir := t.TempDir()
	first := putFile(t, dir, "first.jsp")
	c := testCleaner(t, dir, true)
	stats, err := c.scan(context.Background())
	if err != nil || stats.Matched != 1 || stats.Deleted != 0 {
		t.Fatalf("dry-run stats=%+v err=%v", stats, err)
	}
	assertExists(t, first, true)
	c.dryRun = false
	if _, err := c.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	later := putFile(t, dir, "nested/later.tmp")
	if err := os.Rename(later, later+".JSP"); err != nil {
		t.Fatal(err)
	}
	stats, err = c.scan(context.Background())
	if err != nil || stats.Deleted != 1 {
		t.Fatalf("later scan stats=%+v err=%v", stats, err)
	}
	assertExists(t, later+".JSP", false)
}

func TestJunctionAndSymlinkDoNotEscapeRoot(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "target")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	victim := putFile(t, outside, "keep.jsp")
	junction := filepath.Join(dir, "outside-junction")
	linkCmd := exec.Command("cmd", "/c", "mklink", "/J", junction, outside)
	linkCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := linkCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("cannot create junction fixture: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(junction) })
	c := testCleaner(t, dir, false)
	inside := putFile(t, dir, "delete.jsp")
	stats, err := c.scan(context.Background())
	if err != nil || stats.Deleted != 1 || stats.Skipped < 1 {
		t.Fatalf("junction stats=%+v err=%v", stats, err)
	}
	assertExists(t, victim, true)
	assertExists(t, inside, false)
	if _, err := validateTarget(junction); err == nil {
		t.Fatal("junction root was accepted")
	}
	if err := c.root.Remove(filepath.Join("outside-junction", "keep.jsp")); err == nil {
		t.Fatal("Root.Remove followed an external junction")
	}
	assertExists(t, victim, true)
	link := filepath.Join(dir, "link.jsp")
	if err := os.Symlink(victim, link); err != nil {
		t.Logf("symlink fixture unavailable, junction coverage passed: %v", err)
		return
	}
	t.Cleanup(func() { _ = os.Remove(link) })
	if _, err := c.scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertExists(t, victim, true)
	assertExists(t, link, true)
}

func TestLockedFileRetriesAfterRelease(t *testing.T) {
	dir := t.TempDir()
	p := putFile(t, dir, "locked.jsp")
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		t.Fatal(err)
	}
	h, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if h != syscall.InvalidHandle {
			syscall.CloseHandle(h)
		}
	}()
	c := testCleaner(t, dir, false)
	stats, err := c.scan(context.Background())
	if err != nil || stats.Errors != 1 || stats.Deleted != 0 {
		t.Fatalf("locked stats=%+v err=%v", stats, err)
	}
	assertExists(t, p, true)
	syscall.CloseHandle(h)
	h = syscall.InvalidHandle
	stats, err = c.scan(context.Background())
	if err != nil || stats.Errors != 0 || stats.Deleted != 1 {
		t.Fatalf("retry stats=%+v err=%v", stats, err)
	}
	assertExists(t, p, false)
}

func TestReadOnlyFileAndRootGuards(t *testing.T) {
	dir := t.TempDir()
	p := putFile(t, dir, "readonly.jsp")
	if err := os.Chmod(p, 0400); err != nil {
		t.Fatal(err)
	}
	c := testCleaner(t, dir, false)
	stats, err := c.scan(context.Background())
	if err != nil || stats.Deleted != 1 {
		t.Fatalf("readonly stats=%+v err=%v", stats, err)
	}
	for _, p := range []string{"", ".", "D:", "D:\\", "\\\\server\\share\\dir", filepath.Join(dir, "missing")} {
		if _, err := validateTarget(p); err == nil {
			t.Fatalf("unsafe or nonexistent root accepted: %q", p)
		}
	}
	if isWithin(dir, dir) || isWithin(dir, dir+"-outside") || !isWithin(dir, filepath.Join(dir, "child")) {
		t.Fatal("incorrect root boundary check")
	}
}

func TestCanceledScan(t *testing.T) {
	dir := t.TempDir()
	p := putFile(t, dir, "keep.jsp")
	c := testCleaner(t, dir, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.scan(ctx); err != context.Canceled {
		t.Fatalf("expected canceled, got %v", err)
	}
	assertExists(t, p, true)
}

func TestContinuousProcessFindsNewFile(t *testing.T) {
	if os.Getenv("JSP_CLEANER_TEST_HELPER") == "1" {
		code := run([]string{"-dir", os.Getenv("JSP_CLEANER_TEST_TARGET"), "-interval", "10ms", "-dry-run=false", "-log", os.Getenv("JSP_CLEANER_TEST_LOG")})
		os.Exit(code)
	}
	base := t.TempDir()
	dir := filepath.Join(base, "target")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestContinuousProcessFindsNewFile$")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	cmd.Env = append(os.Environ(), "JSP_CLEANER_TEST_HELPER=1", "JSP_CLEANER_TEST_TARGET="+dir,
		"JSP_CLEANER_TEST_LOG="+filepath.Join(base, "audit.log"))
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	keep := putFile(t, dir, "keep.png")
	audit := filepath.Join(base, "audit.log")
	waitFor(t, func() bool {
		b, _ := os.ReadFile(audit)
		return strings.Contains(string(b), "\"msg\":\"started\"")
	}, "cleaner startup timed out")
	time.Sleep(150 * time.Millisecond)
	newFile := putFile(t, dir, "later/new.jsp")
	waitFor(t, func() bool {
		_, err := os.Lstat(newFile)
		return os.IsNotExist(err)
	}, "new file was not deleted")
	assertExists(t, keep, true)
	logBytes, err := os.ReadFile(audit)
	if err != nil || !bytes.Contains(logBytes, []byte("\"msg\":\"deleted\"")) {
		t.Fatalf("audit missing deletion: %s err=%v", logBytes, err)
	}
}

func waitFor(t *testing.T, done func() bool, message string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(message)
}
