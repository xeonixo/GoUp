package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"goup/internal/remotenode"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	cfg, err := remotenode.LoadConfigFromEnv()
	if err != nil {
		logger.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	agent := remotenode.New(cfg, logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := agent.Run(ctx); err != nil {
		logger.Error("remote node agent failed", "error", err)
		os.Exit(1)
	}
}
