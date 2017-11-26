// log.go - Logging backend.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package log provides a logging backend, based around the go-logging package.
package log

import (
	"fmt"
	"io"
	"io/ioutil"
	goLog "log"
	"os"
	"strings"

	"github.com/op/go-logging"
)

// Backend is a log backend.
type Backend struct {
	w       io.Writer
	backend logging.LeveledBackend
}

// GetLogger returns a per-module logger that writes to the backend.
func (b *Backend) GetLogger(module string) *logging.Logger {
	l := logging.MustGetLogger(module)
	l.SetBackend(b.backend)
	return l
}

// GetGoLogger returns a per-module Go runtime *log.Logger that writes to
// the backend.  Due to limitations of the Go runtime log package, only one
// level is supported per returned Logger.
func (b *Backend) GetGoLogger(module string, level string) *goLog.Logger {
	lvl, err := logLevelFromString(level)
	if err != nil {
		panic("log: GetGoLogger(): Invalid level: " + err.Error())
	}

	w := new(logWriter)
	w.m = b.GetLogger(module)
	w.l = goLog.New(w, "", 0) // Owns w.
	w.lvl = lvl
	return w.l
}

func (b *Backend) GetLogWriter(module string, level string) io.Writer {
	lvl, err := logLevelFromString(level)
	if err != nil {
		panic("log: GetGoLogger(): Invalid level: " + err.Error())
	}

	w := new(logWriter)
	w.m = b.GetLogger(module)
	w.lvl = lvl
	return w
}

// New initializes a logging backend.
func New(f string, level string, disable bool) (*Backend, error) {
	b := new(Backend)

	lvl, err := logLevelFromString(level)
	if err != nil {
		return nil, err
	}

	// Figure out where the log should go to, creating a log file as needed.
	if disable {
		b.w = ioutil.Discard
	} else if f == "" {
		b.w = os.Stdout
	} else {
		const fileMode = 0600

		var err error
		flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
		b.w, err = os.OpenFile(f, flags, fileMode)
		if err != nil {
			return nil, fmt.Errorf("server: failed to create log file: %v", err)
		}
	}

	// Create a new log backend, using the configured output, and initialize
	// the server logger.
	//
	// TODO: Maybe use a custom backend to support rotating the log file.
	logFmt := logging.MustStringFormatter("%{time:15:04:05.000} %{level:.4s} %{module}: %{message}")
	base := logging.NewLogBackend(b.w, "", 0)
	formatted := logging.NewBackendFormatter(base, logFmt)
	b.backend = logging.AddModuleLevel(formatted)
	b.backend.SetLevel(lvl, "")
	return b, nil
}

func logLevelFromString(l string) (logging.Level, error) {
	switch strings.ToUpper(l) {
	case "ERROR":
		return logging.ERROR, nil
	case "WARNING":
		return logging.WARNING, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "INFO":
		return logging.INFO, nil
	case "DEBUG":
		return logging.DEBUG, nil
	default:
		return logging.CRITICAL, fmt.Errorf("log: invalid level: '%v'", l)
	}
}

type logWriter struct {
	m   *logging.Logger
	l   *goLog.Logger
	lvl logging.Level
}

func (w logWriter) Write(p []byte) (n int, err error) {
	// The `log` package will always pass a byte array with a newline at
	// the end, so it needs to be stripped off.
	s := strings.TrimSpace(string(p))
	if len(s) == 0 {
		return
	}

	switch w.lvl {
	case logging.ERROR:
		w.m.Error(s)
	case logging.WARNING:
		w.m.Warning(s)
	case logging.NOTICE:
		w.m.Notice(s)
	case logging.INFO:
		w.m.Info(s)
	case logging.DEBUG:
		w.m.Debug(s)
	case logging.CRITICAL:
		w.m.Critical(s)
	default:
		panic("BUG: Invalid log level in logWriter.Write()")
	}

	return len(p), nil
}
