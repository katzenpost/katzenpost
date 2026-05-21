// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// clear-chaos stops and removes every container whose name begins with
// `katzenpost_pumba_`. It is functionally equivalent to
// `make pumba-stop` and exists so the chaos lifecycle orchestrator can
// drive teardown without shelling out to make.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/katzenpost/katzenpost/chaos"
)

func main() {
	docker := flag.String("docker", "", "container runtime binary; empty auto-detects podman or docker")
	flag.Parse()

	rt := chaos.DefaultRuntime()
	if *docker != "" {
		rt.Docker = *docker
	}

	if err := chaos.Clear(context.Background(), rt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("clear-chaos: every katzenpost_pumba_* container has been stopped and removed")
}
