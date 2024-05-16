// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// standalone client daemon
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/carlmjohnson/versioninfo"
	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
)

func main() {
	var configFile string

	flag.StringVar(&configFile, "c", "", "configuration file")
	version := flag.Bool("v", false, "Get version info.")
	flag.Parse()

	if *version {
		fmt.Printf("version is %s\n", versioninfo.Short())
		return
	}

	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(err)
	}

	d, err := client2.NewDaemon(cfg)
	if err != nil {
		panic(err)
	}

	err = d.Start()
	if err != nil {
		panic(err)
	}
	defer d.Halt()

	go func() {
		<-haltCh
		d.Halt()
	}()

	d.Wait()
}
