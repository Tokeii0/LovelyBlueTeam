package main

import (
	"context"
	"fmt"
	"lovely-honeypots/uds-agent/internal/config"
)

type simulationResult struct{ hostname string }

func simulate(ctx context.Context, cfg config.Config, stage func(string), detail func(string)) (*simulationResult, error) {
	if cfg.Profile != "synthetic" {
		return nil, fmt.Errorf("only the synthetic profile is supported")
	}
	for _, name := range []string{"fixture", "channels", "queue", "response", "complete"} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		stage(name)
	}
	detail("本次结果全部来自内置合成数据；未执行网络连接或系统采集。")
	return &simulationResult{hostname: "DEMO-HOST"}, nil
}
