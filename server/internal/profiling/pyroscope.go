//go:build pyroscope
// +build pyroscope

package profiling

import (
	"errors"
	"gopkg.in/op/go-logging.v1"
	"os"

	"github.com/grafana/pyroscope-go"
)

// Start initializes Pyroscope profiling.
func Start(log *logging.Logger) error {
	log.Info("Starting Pyroscope")

	serverAddress := os.Getenv("PYROSCOPE_SERVER_ADDRESS")
	if serverAddress == "" {
		return errors.New("PYROSCOPE_SERVER_ADDRESS is not set")
	}

	appName := os.Getenv("PYROSCOPE_APP_NAME")
	if appName == "" {
		return errors.New("PYROSCOPE_APP_NAME is not set")
	}

	serviceTag := os.Getenv("PYROSCOPE_SERVICE_TAG")
	if serviceTag == "" {
		return errors.New("PYROSCOPE_SERVICE_TAG is not set")
	}

	_, err := pyroscope.Start(pyroscope.Config{
		ApplicationName: appName,
		ServerAddress:   serverAddress,
		Logger:          pyroscope.StandardLogger,
		Tags: map[string]string{
			"service": serviceTag,
		},
	})
	if err != nil {
		return err
	}
	log.Infof("Pyroscope started successfully at %s, app name: %s, service tag: %s", serverAddress, appName, serviceTag)
	return nil
}
