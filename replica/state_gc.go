// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"errors"
	"time"

	"github.com/linxGnu/grocksdb"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// gcInterval is how often the box-record GC worker fires. A
// DeleteRange over an empty span is cheap, so a sub-epoch tick is
// fine and means a freshly started process catches up promptly
// without having to track the next epoch boundary itself.
var gcInterval = replicaCommon.ReplicaEpochPeriod / 28

// WipeStaleBoxes deletes every stored box whose replica-epoch prefix
// falls outside the retention window. With the current rule we keep
// the current and previous replica epochs, so this drops everything
// strictly older than the previous epoch.
func (s *state) WipeStaleBoxes() error {
	if s.db == nil {
		return errors.New(errDatabaseClosed)
	}
	cur := currentReplicaEpoch()
	if cur < 2 {
		// Nothing predates the kept window yet.
		return nil
	}
	cutoff := cur - 1
	start := epochPrefix(0)
	end := epochPrefix(cutoff)

	cf := s.db.GetDefaultColumnFamily()
	defer cf.Destroy()

	wo := grocksdb.NewDefaultWriteOptions()
	defer wo.Destroy()

	s.log.Noticef("state: wiping stored boxes for replica epochs < %d", cutoff)
	if err := s.db.DeleteRangeCF(wo, cf, start, end); err != nil {
		s.log.Errorf("state: DeleteRangeCF failed during GC: %s", err)
		return err
	}
	return nil
}

// startGCWorker launches the periodic box-record GC goroutine.
// Halts when state.Close is called.
func (s *state) startGCWorker() {
	s.Go(s.gcWorker)
}

func (s *state) gcWorker() {
	timer := time.NewTimer(gcInterval)
	defer timer.Stop()
	for {
		select {
		case <-s.HaltCh():
			s.log.Debug("state: GC worker terminating gracefully.")
			return
		case <-timer.C:
		}
		if err := s.WipeStaleBoxes(); err != nil {
			s.log.Errorf("state: GC failed: %s", err)
		}
		timer.Reset(gcInterval)
	}
}
