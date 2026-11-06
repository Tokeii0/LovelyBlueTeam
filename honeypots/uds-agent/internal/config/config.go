package config

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

type Config struct {
	Profile string `json:"profile"`
}

// LoadFile opens only the explicitly requested small demo configuration.
func LoadFile(path string) (Config, error) {
	var cfg Config
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("cannot open requested demo config")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return cfg, errors.New("invalid demo config file")
	}
	d := json.NewDecoder(io.LimitReader(f, 4097))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || cfg.Profile != "synthetic" {
		return Config{}, errors.New("expected profile=synthetic only")
	}
	var trailing any
	if d.Decode(&trailing) != io.EOF {
		return Config{}, errors.New("unexpected trailing config content")
	}
	return cfg, nil
}
