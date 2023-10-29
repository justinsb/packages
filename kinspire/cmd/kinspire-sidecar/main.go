package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/justinsb/packages/kinspire/pkg/client"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	flag.Parse()

	if err := client.SPIFFE.Init(ctx); err != nil {
		return err
	}

	for {
		time.Sleep(5 * time.Second)
	}

	return nil
}
