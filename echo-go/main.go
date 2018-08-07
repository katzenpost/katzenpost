package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/hashicorp/go-plugin"
	common "github.com/katzenpost/server/common-plugin"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("echo-go")

var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)

func stringToLogLevel(level string) (logging.Level, error) {
	switch level {
	case "DEBUG":
		return logging.DEBUG, nil
	case "INFO":
		return logging.INFO, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "WARNING":
		return logging.WARNING, nil
	case "ERROR":
		return logging.ERROR, nil
	case "CRITICAL":
		return logging.CRITICAL, nil
	}
	return -1, fmt.Errorf("invalid logging level %s", level)
}

func setupLoggerBackend(level logging.Level, writer io.Writer) logging.LeveledBackend {
	format := logFormat
	backend := logging.NewLogBackend(writer, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(level, "echo-go")
	return leveler
}

type Echo struct{}

func (Echo) OnRequest(payload []byte, hasSURB bool) ([]byte, error) {
	log.Debugf("OnRequest invoked, hasSURB is %v", hasSURB)
	if !hasSURB {
		return nil, errors.New("request received without SURB, error")
	}
	return payload, nil
}

func main() {
	var logLevel string
	var logDir string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	level, err := stringToLogLevel(logLevel)
	if err != nil {
		fmt.Println("Invalid logging-level specified.")
		os.Exit(1)
	}

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
	logFile := path.Join(logDir, fmt.Sprintf("echo-go.%d.log", os.Getpid()))
	f, err := os.Create(logFile)
	logBackend := setupLoggerBackend(level, f)
	log.SetBackend(logBackend)
	log.Debug("echo-go server started.")

	// Run plugin server.
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: common.Handshake,
		Plugins: map[string]plugin.Plugin{
			common.KaetzchenService: &common.KaetzchenPlugin{Impl: &Echo{}},
		},
		GRPCServer: plugin.DefaultGRPCServer,
	})
}
