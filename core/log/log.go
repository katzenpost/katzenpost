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
	"sync"

	"gopkg.in/op/go-logging.v1"
)

type discardCloser struct {
	io.WriteCloser
	discard io.Writer
}

func (d *discardCloser) Close() error {
	return nil
}

func newDiscardCloser() *discardCloser {
	d := new(discardCloser)
	d.discard = ioutil.Discard
	return d
}

// Backend is a log backend.
type Backend struct {
	logging.LeveledBackend
	sync.RWMutex

	_backend logging.LeveledBackend
	w        io.WriteCloser

	file    string
	level   string
	disable bool
}

// Log is used to log a message as per
// the logging.Backend interface.
func (b *Backend) Log(level logging.Level, calldepth int, record *logging.Record) error {
	b.RLock()
	defer b.RUnlock()
	return b._backend.Log(level, calldepth, record)
}

// GetLevel returns the logging level for the specified module
// as per the logging.Leveled interface.
func (b *Backend) GetLevel(level string) logging.Level {
	b.RLock()
	defer b.RUnlock()
	return b._backend.GetLevel(level)
}

// SetLevel sets the logging level for the specified module.
// The module corresponds to the string specified in GetLogger.
// We use this function as part of our implementation of the
// logging.Leveled interface.
func (b *Backend) SetLevel(level logging.Level, module string) {
	b.RLock()
	defer b.RUnlock()
	b._backend.SetLevel(level, module)
}

// IsEnabledFor returns true if the logger is enabled for the given level.
// We use this function as part of our implementation of the
// logging.Leveled interface.
func (b *Backend) IsEnabledFor(level logging.Level, module string) bool {
	b.RLock()
	defer b.RUnlock()
	return b._backend.IsEnabledFor(level, module)
}

// GetLogger returns a per-module logger that writes to the backend.
func (b *Backend) GetLogger(module string) *logging.Logger {
	l := logging.MustGetLogger(module)
	l.SetBackend(b)
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

// GetLogWriter returns a per-module io.Writer that writes to the backend at
// the provided level.
func (b *Backend) GetLogWriter(module string, level string) io.Writer {
	lvl, err := logLevelFromString(level)
	if err != nil {
		panic("log: GetLogWriter(): Invalid level: " + err.Error())
	}

	w := new(logWriter)
	w.m = b.GetLogger(module)
	w.lvl = lvl
	return w
}

// Rotate simply reopens the log file for writing
// and should be used to implement log rotation
// where this is invoked upon HUP signal for example.
func (b *Backend) Rotate() error {
	b.Lock()
	defer b.Unlock()

	err := b.w.Close()
	if err != nil {
		return err
	}
	b.newBackend()
	return nil
}

func (b *Backend) newBackend() error {
	lvl, err := logLevelFromString(b.level)
	if err != nil {
		return err
	}

	// Figure out where the log should go to, creating a log file as needed.
	if b.disable {
		b.w = newDiscardCloser()
	} else if b.file == "" {
		b.w = os.Stdout
	} else {
		const fileMode = 0600

		var err error
		flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
		b.w, err = os.OpenFile(b.file, flags, fileMode)
		if err != nil {
			return fmt.Errorf("server: failed to create log file: %v", err)
		}
	}

	// Create a new log backend, using the configured output, and initialize
	// the server logger.
	logFmt := logging.MustStringFormatter("%{time:15:04:05.000} %{level:.4s} %{module}: %{message}")
	base := logging.NewLogBackend(b.w, "", 0)
	formatted := logging.NewBackendFormatter(base, logFmt)
	b._backend = logging.AddModuleLevel(formatted)
	b._backend.SetLevel(lvl, "")
	return nil
}

// New initializes a logging backend.
func New(f string, level string, disable bool) (*Backend, error) {
	b := new(Backend)
	b.file = f
	b.level = level
	b.disable = disable
	err := b.newBackend()
	if err != nil {
		return nil, err
	}
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
