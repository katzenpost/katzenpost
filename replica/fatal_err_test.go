// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

// Shutdown used to close fatalErrCh, so a reporter that lost the race
// panicked on a send to a closed channel. Leaving it open is only safe
// because the send is non-blocking: after Shutdown the watcher is gone
// and nothing will ever drain it again.
func TestReportFatalAfterShutdown(t *testing.T) {
	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	s := &Server{
		logBackend: logBackend,
		log:        logBackend.GetLogger("fatal_err_test"),
		fatalErrCh: make(chan error, 1),
		haltedCh:   make(chan interface{}),
	}
	s.Shutdown()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.reportFatal(errors.New("first"))
		s.reportFatal(errors.New("second"))
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reportFatal blocked after shutdown")
	}
}
