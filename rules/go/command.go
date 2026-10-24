package main

import (
	"context"
	"fmt"
	"os/exec"
)

func run(ctx context.Context, host string) {
	// ruleid: openasy.go.command-injection
	exec.Command("sh", "-c", "ping -c 1 "+host).Run()
	// ruleid: openasy.go.command-injection
	exec.CommandContext(ctx, "bash", "-c", fmt.Sprintf("tar xf %s", host)).Run()
	// ok: openasy.go.command-injection
	exec.Command("ping", "-c", "1", host).Run()
	// ok: openasy.go.command-injection
	exec.Command("sh", "-c", "uptime").Run()
}
