package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"lovely-honeypots/uds-agent/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSimulationUsesSyntheticIdentityAndRespectsCancellation(t *testing.T) {
	res, err := simulate(context.Background(), config.Config{Profile: "synthetic"}, func(string) {}, func(string) {})
	if err != nil || res.hostname != "DEMO-HOST" {
		t.Fatal("non-demo identity")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = simulate(ctx, config.Config{Profile: "synthetic"}, func(string) {}, func(string) {}); err == nil {
		t.Fatal("cancellation ignored")
	}
	data, _ := json.Marshal(fakePatient("TEST-PATIENT-001"))
	for _, want := range []string{"000000000000000000", "测试患者", "TEST-PHONE", "合成示例地址"} {
		if !strings.Contains(string(data), want) {
			t.Fatalf("missing synthetic marker %s", want)
		}
	}
	if !strings.HasPrefix(fakeSessionToken(), "DEMO-ONLY-") {
		t.Fatal("unexpected authentication token")
	}
}

func TestExplicitConfigValidation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "demo.json")
	for _, body := range []string{`{"profile":"synthetic"}`, `{"profile":"synthetic","proxy":"fixture"}`, `{}`, `{"profile":"synthetic"}{}`, strings.Repeat("x", 5000)} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := config.LoadFile(path)
		if (err == nil) != (body == `{"profile":"synthetic"}`) {
			t.Fatal("unexpected config validation")
		}
	}
	if _, err := loadConfig(&cliOptions{cfgPath: filepath.Join(dir, "missing.json")}); err == nil {
		t.Fatal("missing config silently ignored")
	}
	if _, err := loadConfig(&cliOptions{proxy: "http://127.0.0.1:9"}); err == nil {
		t.Fatal("network proxy accepted")
	}
}

func TestExportsContainFixturesAndRefuseOverwrite(t *testing.T) {
	t.Chdir(t.TempDir())
	path, _, err := writeDiagBundle(&simulationResult{hostname: "DEMO-HOST"})
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if len(z.File) != 3 {
		t.Fatal("unexpected diagnostic contents")
	}
	for _, f := range z.File {
		if f.Name != "agent.log" && f.Name != "channels.json" && f.Name != "env.json" {
			t.Fatal("unexpected host file")
		}
	}
	o := &cliOptions{args: []string{"export.json"}}
	if _, err = writeExport(o); err != nil {
		t.Fatal(err)
	}
	if _, err = writeExport(o); err == nil {
		t.Fatal("existing export overwritten")
	}
	data, _ := os.ReadFile("export.json")
	if !strings.Contains(string(data), `"synthetic": true`) {
		t.Fatal("missing synthetic flag")
	}
}
