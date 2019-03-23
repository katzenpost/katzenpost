package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/hashicorp/go-plugin"
	"github.com/katzenpost/core/log"
	common "github.com/katzenpost/server/grpcplugin"
)

func main() {
	var logLevel string
	var logDir string
	var dwellTime string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&dwellTime, "dwell_time", "336h", "ciphertext max dwell time before garbage collection")
	flag.Parse()

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("panda.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		fmt.Println("Failure to create a logBackend.")
		os.Exit(1)
	}
	logger := logBackend.GetLogger("panda")
	logger.Info("panda server started")

	duration, err := time.ParseDuration(dwellTime)
	if err != nil {
		fmt.Println("failure to parse duration string")
		os.Exit(1)
	}

	// Run plugin server.
	panda := New(duration, logger)
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: common.Handshake,
		Plugins: map[string]plugin.Plugin{
			common.KaetzchenService: &common.KaetzchenPlugin{Impl: panda},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
