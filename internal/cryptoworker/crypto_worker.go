// crypto_worker.go - Katzenpost server crypto worker.
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

// Package cryptoworker implements the Katzenpost Sphinx crypto worker.
package cryptoworker

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/internal/constants"
	"github.com/katzenpost/server/internal/glue"
	"github.com/katzenpost/server/internal/mixkey"
	"github.com/katzenpost/server/internal/packet"
	"gopkg.in/op/go-logging.v1"
)

// Worker is a Sphinx crypto worker instance.
type Worker struct {
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	mixKeys map[uint64]*mixkey.MixKey

	incomingCh <-chan interface{}
	updateCh   chan bool
}

// UpdateMixKeys forces the Worker to re-shadow it's copy of the mix key(s).
func (w *Worker) UpdateMixKeys() {
	// This is a blocking call, because bad things will happen if the keys
	// happen to get out of sync.
	w.updateCh <- true
}

func (w *Worker) doUnwrap(pkt *packet.Packet) error {
	const gracePeriod = 2 * time.Minute

	// Figure out the candidate mix private keys for this packet.
	keys := make([]*mixkey.MixKey, 0, 2)
	epoch, elapsed, till := epochtime.Now()
	k, ok := w.mixKeys[epoch]
	if !ok || k == nil {
		// There always will be a key for the current epoch, since
		// key generation happens multiple epochs in advance.
		return fmt.Errorf("crypto: No key for epoch %v", epoch)
	}
	keys = append(keys, k)

	// At certain times, this needs to also look at the previous
	// or next epoch(s) keys, if they exist.
	if elapsed < gracePeriod {
		// Less than gracePeriod into the current epoch, the previous
		// epoch's key should also be accepted.
		k, ok = w.mixKeys[epoch-1]
	} else if till < gracePeriod {
		// Less than gracePeriod to the next epoch, the next epoch's
		// key should also be accepted.
		k, ok = w.mixKeys[epoch+1]
	} else {
		// Only one key to use.
		k = nil
		ok = false
	}
	if ok && k != nil {
		// Not having other keys is fine, regardless of if we are
		// in the grace period, if a packet happens to get dropped,
		// oh well.
		keys = append(keys, k)
	}

	var lastErr error
	for _, k = range keys {
		startAt := monotime.Now()

		// TODO/perf: payload is a new heap allocation if it's returned,
		// though that should only happen if this is a provider.
		payload, tag, cmds, err := sphinx.Unwrap(k.PrivateKey(), pkt.Raw)
		unwrapAt := monotime.Now()

		w.log.Debugf("Packet: %v (Unwrap took: %v)", pkt.ID, unwrapAt-startAt)

		// Decryption failures can result from picking the wrong key.
		if err != nil {
			// So save the error and try the next key if possible.
			lastErr = err
			continue
		}

		// Stash the payload commands.  Even if we end up rejecting the
		// packet, pkt.dispose() has to get a chance to deallocate them
		// nicely.
		if err = pkt.Set(payload, cmds); err != nil {
			lastErr = err
			break
		}

		// Check for replayed packets.
		if k.IsReplay(tag) {
			// The packet decrypted successfully, the MAC was valid, and the
			// tag was seen before, therefore drop the packet as a replay.
			lastErr = errors.New("crypto: Packet is a replay")
			break
		}

		w.log.Debugf("Packet: %v (IsReplay took: %v)", pkt.ID, monotime.Now()-unwrapAt)

		return nil
	}

	// Return the last error to signal Unwrap() failure.
	if lastErr == nil {
		lastErr = errors.New("BUG: crypto: Out of candidate keys for Unwrap(), no saved error")
	}
	return lastErr
}

func (w *Worker) worker() {
	isProvider := w.glue.Config().Server.IsProvider
	unwrapSlack := time.Duration(w.glue.Config().Debug.UnwrapDelay) * time.Millisecond
	defer w.derefKeys()

	for {
		// This is where the bulk of the inbound packet processing happens,
		// and the only significant source of parallelism.
		var pkt *packet.Packet

		select {
		case <-w.HaltCh():
			w.log.Debugf("Terminating gracefully.")
			return
		case <-w.updateCh:
			w.log.Debugf("Updating mix keys.")
			w.glue.MixKeys().Shadow(w.mixKeys)
			continue
		case e := <-w.incomingCh:
			pkt = e.(*packet.Packet)
		}

		// This deliberately ignores the cryptographic processing time, since
		// it (should) be constant across packets, and I'll go crazy trying
		// to account for everything that impacts the actual delay vs
		// requested.
		now := monotime.Now()

		// Drop the packet if it has been sitting in the queue waiting to
		// be unwrapped for way too long.
		if unwrapDelay := now - pkt.RecvAt; unwrapDelay > unwrapSlack {
			w.log.Debugf("Dropping packet: %v (Spent %v waiting for Unwrap())", pkt.ID, unwrapDelay)
			pkt.Dispose()
			continue
		} else {
			w.log.Debugf("Packet: %v (Unwrap queue delay: %v)", pkt.ID, unwrapDelay)
		}

		// Attempt to unwrap the packet.
		w.log.Debugf("Attempting to unwrap packet: %v", pkt.ID)
		if err := w.doUnwrap(pkt); err != nil {
			w.log.Debugf("Dropping packet: %v (%v)", pkt.ID, err)
			pkt.Dispose()
			continue
		}
		w.log.Debugf("Packet: %v (doUnwrap took: %v)", pkt.ID, monotime.Now()-now)

		// The common (in the both most likely, and done by all modes) case
		// is that the packet is destined for another node.
		if pkt.IsForward() {
			if pkt.Payload != nil {
				w.log.Debugf("Dropping packet: %v (Unwrap() returned payload)", pkt.ID)
				pkt.Dispose()
				continue
			}
			if pkt.MustTerminate {
				w.log.Debugf("Dropping packet: %v (Provider received forward packet from mix)", pkt.ID)
				pkt.Dispose()
				continue
			}

			// Check and adjust the delay for queue dwell time.
			pkt.Delay = time.Duration(pkt.NodeDelay.Delay) * time.Millisecond
			if pkt.Delay > constants.NumMixKeys*epochtime.Period {
				w.log.Debugf("Dropping packet: %v (Delay %v is past what is possible)", pkt.ID, pkt.Delay)
				pkt.Dispose()
				continue
			}
			dwellTime := now - pkt.RecvAt
			if pkt.Delay > dwellTime {
				pkt.Delay -= dwellTime
			} else {
				// Eeep, the dwell time has exceeded the user requested delay.
				//
				// TODO: Either can drop or dispatch the packet immediately,
				// I'm not sure which is better behavior.
				pkt.Delay = 0
			}

			// Hand off to the scheduler.
			w.log.Debugf("Dispatching packet: %v", pkt.ID)
			w.glue.Scheduler().OnPacket(pkt)
			continue
		} else if !isProvider {
			// Mixes will only ever see forward commands.
			w.log.Debugf("Dropping mix packet: %v (%v)", pkt.ID, pkt.CmdsToString())
			pkt.Dispose()
			continue
		}

		// This node is a provider and the packet is not destined for another
		// node.  Both of the operations here end up hitting up disk among
		// other things, so are just shunted off to a separate worker so that
		// packet processing does not get blocked.

		if pkt.MustForward {
			w.log.Debugf("Dropping client packet: %v (Send to local user)", pkt.ID)
			pkt.Dispose()
			continue
		}

		// Toss the packets over to the provider backend.
		// Note: Callee takes ownership of pkt.
		if pkt.IsToUser() || pkt.IsUnreliableToUser() || pkt.IsSURBReply() {
			w.log.Debugf("Handing off user destined packet: %v", pkt.ID)
			pkt.DispatchAt = now
			w.glue.Provider().OnPacket(pkt)
		} else {
			w.log.Debugf("Dropping user packet: %v (%v)", pkt.ID, pkt.CmdsToString())
			pkt.Dispose()
		}
	}

	// NOTREACHED
}

func (w *Worker) derefKeys() {
	for _, v := range w.mixKeys {
		v.Deref()
	}
}

// New constructs a new Worker instance.
func New(glue glue.Glue, incomingCh <-chan interface{}, id int) *Worker {
	w := &Worker{
		glue:       glue,
		log:        glue.LogBackend().GetLogger(fmt.Sprintf("crypto:%d", id)),
		mixKeys:    make(map[uint64]*mixkey.MixKey),
		incomingCh: incomingCh,
		updateCh:   make(chan bool),
	}

	w.glue.MixKeys().Shadow(w.mixKeys)
	w.Go(w.worker)
	return w
}
