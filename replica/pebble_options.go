// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"

	"github.com/cockroachdb/pebble"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/replica/instrument"
)

// pebbleBlockCacheSize is the size of the block cache shared by the box
// and metadata databases. Pebble defaults to 8 MiB per database, which
// would hand the metadata database, which holds two keys, a cache of
// its own; one shared cache of that size serves both.
const pebbleBlockCacheSize = 8 << 20

// pebbleLogger routes Pebble's operational messages into the replica's
// log backend. Pebble's default logger writes to the Go standard
// library log and calls os.Exit on Fatalf, so without this the
// replica's storage messages bypass the configured log file entirely
// and a background storage error terminates the process outside
// Server.halt.
type pebbleLogger struct {
	log *logging.Logger
}

// Infof carries Pebble's per-job chatter: WAL replay, flush and
// compaction progress. It is verbose, so it is logged at DEBUG.
func (l *pebbleLogger) Infof(format string, args ...interface{}) {
	l.log.Debugf("pebble: "+format, args...)
}

// Fatalf must not return. Pebble treats it as terminal and carries on
// if it does: applyInternal logs a fatal commit error through Fatalf
// and then returns nil, so a failed commit would be reported to the
// caller as a successful one. Log through the replica's backend first,
// so the failure reaches the log file rather than only stderr, then
// panic, which at least yields a stack trace where Pebble's default
// logger would have called os.Exit(1).
func (l *pebbleLogger) Fatalf(format string, args ...interface{}) {
	msg := fmt.Sprintf("pebble: "+format, args...)
	l.log.Critical("%s", msg)
	instrument.DroppedByReason("pebble_fatal")
	panic(msg)
}

// pebbleOptions returns the options both replica databases are opened
// with. The caller owns cache and must Unref it once every database
// opened with these options has been closed.
func (s *state) pebbleOptions(cache *pebble.Cache) *pebble.Options {
	return &pebble.Options{
		Cache:  cache,
		Logger: &pebbleLogger{log: s.log},
		EventListener: &pebble.EventListener{
			// Flush and compaction failures are otherwise silent.
			BackgroundError: func(err error) {
				s.log.Errorf("state: pebble background error: %s", err)
				instrument.DroppedByReason("pebble_background_error")
			},
		},
	}
}
