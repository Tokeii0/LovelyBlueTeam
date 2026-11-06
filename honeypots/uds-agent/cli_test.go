package main

import (
	"slices"
	"strings"
	"testing"
)

func TestParseCLIBasic(t *testing.T) {
	o, err := parseCLI(nil)
	if err != nil || o.command != "" {
		t.Fatalf("empty args: %+v %v", o, err)
	}
	o, err = parseCLI([]string{"status", "--json"})
	if err != nil || o.command != "status" || !o.json {
		t.Fatalf("status --json: %+v %v", o, err)
	}
	o, err = parseCLI([]string{"--json", "list"})
	if err != nil || o.command != "list" || !o.json {
		t.Fatalf("--json list: %+v %v", o, err)
	}
	o, err = parseCLI([]string{"-h"})
	if err != nil || !o.help {
		t.Fatalf("-h: %+v", o)
	}
	for _, a := range [][]string{{"--help"}, {"-?"}, {"/?"}} {
		if o, err = parseCLI(a); err != nil || !o.help {
			t.Fatalf("%v should be help: %+v", a, o)
		}
	}
	for _, a := range [][]string{{"--version"}, {"-V"}} {
		if o, err = parseCLI(a); err != nil || !o.ver {
			t.Fatalf("%v should be version: %+v", a, o)
		}
	}
}

func TestParseCLIJSONAliases(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--json"},
		{"list", "-o", "json"},
		{"list", "-o=json"},
		{"list", "--output", "json"},
		{"list", "--format", "json"},
		{"list", "--format=json"},
	} {
		o, err := parseCLI(args)
		if err != nil || o.command != "list" || !o.json {
			t.Fatalf("%v: %+v err=%v", args, o, err)
		}
	}
}

func TestParseCLITimeoutAndValues(t *testing.T) {
	o, err := parseCLI([]string{"test", "--timeout", "60"})
	if err != nil || o.timeout != 60 {
		t.Fatalf("timeout: %+v %v", o, err)
	}
	o, err = parseCLI([]string{"test", "--timeout=90", "-t", "45"})
	if err != nil || o.timeout != 45 {
		t.Fatalf("timeout override: %+v %v", o, err)
	}
	o, err = parseCLI([]string{"test", "--timeout", "9999"})
	if err != nil || o.timeout != 120 {
		t.Fatalf("timeout clamp: %+v", o)
	}
	o, err = parseCLI([]string{"test", "--timeout", "1"})
	if err != nil || o.timeout != 5 {
		t.Fatalf("timeout floor: %+v", o)
	}
	if _, err = parseCLI([]string{"test", "--timeout", "abc"}); err == nil {
		t.Fatal("bad timeout should error")
	}
}

func TestParseCLIPositionalAndIgnored(t *testing.T) {
	o, err := parseCLI([]string{"export", "out.json"})
	if err != nil || o.command != "export" || len(o.args) != 1 || o.args[0] != "out.json" {
		t.Fatalf("export arg: %+v", o)
	}
	// -o <非格式值> 按位置参数处理（导出目标文件名）。
	o, err = parseCLI([]string{"export", "-o", "cfg-snap.json"})
	if err != nil || len(o.args) != 1 || o.args[0] != "cfg-snap.json" {
		t.Fatalf("export -o file: %+v", o)
	}
	// --user/--password/--token 等被接受并忽略，其值不进入位置参数。
	o, err = parseCLI([]string{"status", "--user", "admin", "--password", "s3cret", "--token", "x"})
	if err != nil || o.command != "status" || len(o.args) != 0 {
		t.Fatalf("ignored value flags leaked: %+v", o)
	}
	// 未知选项被容忍。
	o, err = parseCLI([]string{"status", "--bogus", "--frobnicate=1"})
	if err != nil || o.command != "status" {
		t.Fatalf("unknown flags: %+v %v", o, err)
	}
	// -- 之后全部按位置参数。
	o, err = parseCLI([]string{"export", "--", "--weird"})
	if err != nil || len(o.args) != 1 || o.args[0] != "--weird" {
		t.Fatalf("double dash: %+v", o)
	}
}

func TestCommandTables(t *testing.T) {
	for name, spec := range cmdTable {
		if spec.desc == "" {
			t.Fatalf("command %s missing desc", name)
		}
		for i, s := range spec.stages {
			if s == "" {
				t.Fatalf("command %s stage %d empty", name, i)
			}
		}
		if spec.runResult == nil {
			t.Fatalf("command %s missing runResult", name)
		}
	}
	for alias, canon := range cmdAliases {
		if _, ok := cmdTable[canon]; !ok {
			t.Fatalf("alias %s -> %s not a command", alias, canon)
		}
	}
	wantCmds := []string{"status", "test", "diagnose", "sync", "auth", "patient", "lis", "invoke", "list", "export", "run"}
	for _, c := range wantCmds {
		if _, ok := cmdTable[c]; !ok {
			t.Fatalf("missing command %s", c)
		}
	}
	if !strings.Contains(helpText, "%s") {
		t.Fatal("helpText lost format placeholders")
	}
}

func TestChannelDataConsistency(t *testing.T) {
	total, normal, warn, disabled := channelCounts()
	if total != len(udsChannels) || normal+warn+disabled != total {
		t.Fatalf("channel counts inconsistent")
	}
	if pendingTotal() < 0 {
		t.Fatal("pendingTotal negative")
	}
	ids := map[string]bool{}
	for _, c := range udsChannels {
		if ids[c.ID] {
			t.Fatalf("duplicate channel id %s", c.ID)
		}
		ids[c.ID] = true
	}
	if !slices.Contains([]string{"Oracle", "MySQL", "WebApi"}, udsChannels[0].Agent) && udsChannels[0].Agent == "" {
		t.Fatal("agent type empty")
	}
}

type errString string

func (e errString) Error() string { return string(e) }
