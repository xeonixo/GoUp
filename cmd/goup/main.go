package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"

	"goup/internal/app"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	application, err := app.New(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer application.Close()

	if err := application.Run(ctx); err != nil {
		log.Fatal(err)
	}
}
