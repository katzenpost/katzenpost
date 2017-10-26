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

package server

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/monotime"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/server/internal/mixkey"
	"github.com/op/go-logging"
)

type cryptoWorker struct {
	sync.WaitGroup

	s   *Server
	log *logging.Logger

	mixKeys map[uint64]*mixkey.MixKey

	updateCh chan bool
	haltCh   chan interface{}
}

func (w *cryptoWorker) updateMixKeys() {
	// This is a blocking call, because bad things will happen if the keys
	// happen to get out of sync.
	w.updateCh <- true
}

func (w *cryptoWorker) halt() {
	close(w.haltCh)
	w.Wait()
}

func (w *cryptoWorker) doUnwrap(pkt *packet) error {
	// Figure out the candidate mix private keys for this packet.
	keys := make([]*mixkey.MixKey, 0, 2)
	if w.s.cfg.Debug.DisableKeyRotation {
		keys = append(keys, w.mixKeys[debugStaticEpoch])
	} else {
		const gracePeriod = 2 * time.Minute

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

	}

	var lastErr error
	for _, k := range keys {
		// TODO/perf: payload is a new heap allocation if it's returned,
		// though that should only happen if this is a provider.
		payload, tag, cmds, err := sphinx.Unwrap(k.PrivateKey(), pkt.raw)

		// Decryption failures can result from picking the wrong key.
		if err != nil {
			// So save the error and try the next key if possible.
			lastErr = err
			continue
		}

		// Stash the payload commands.  Even if we end up rejecting the
		// packet, pkt.dispose() has to get a chance to deallocate them
		// nicely.
		pkt.payload = payload
		pkt.cmds = cmds

		// Check for replayed packets.
		if k.IsReplay(tag) {
			// The packet decrypted successfully, the MAC was valid, and the
			// tag was seen before, therefore drop the packet as a replay.
			lastErr = errors.New("crypto: Packet is a replay")
			break
		}

		return nil
	}

	// Return the last error to signal Unwrap() failure.
	if lastErr == nil {
		panic("BUG: Out of candidate keys for Unwrap(), no saved error")
	}
	return lastErr
}

func (w *cryptoWorker) worker() {
	inCh := w.s.inboundPackets.Out()
	defer func() {
		w.derefKeys()
		w.Done()
	}()
	for {
		// This is where the bulk of the inbound packet processing happens,
		// and the only significant source of parallelism.
		var pkt *packet

		select {
		case <-w.haltCh:
			w.log.Debugf("Terminating gracefully.")
			return
		case <-w.updateCh:
			if w.s.cfg.Debug.DisableKeyRotation {
				panic("BUG: Key update requested with disabled key rotation")
			}
			w.log.Debugf("Updating mix keys.")
			w.s.mixKeys.shadow(w.mixKeys)
			continue
		case e := <-inCh:
			pkt = e.(*packet)
		}

		// This deliberately ignores the cryptographic processing time, since
		// it (should) be constant across packets, and I'll go crazy trying
		// to account for everything that impacts the actual delay vs
		// requested.
		now := monotime.Now()

		// TODO/perf: This would be the logical place to drop packets if
		// there's noticable overload, probably by measuring queue
		// dwell time from when the packet was received.

		// Attempt to unwrap the packet.
		w.log.Debugf("Attempting to unwrap packet: %v", pkt.id)
		if err := w.doUnwrap(pkt); err != nil {
			w.log.Debugf("Dropping packet: %v (%v)", pkt.id, err)
			pkt.dispose()
			continue
		}

		// At this point, we have a packet that's been unwrapped, with
		// the modified packet, paylod (if any), and the vector of Sphinx
		// commands, that is not a replay.  Examine the list of commands to
		// see what kind of packet it is, and then handle it as appropriate.
		if err := pkt.splitCommands(); err != nil {
			w.log.Debugf("Dropping packet: %v (%v)", pkt.id, err)
			pkt.dispose()
			continue
		}

		// The common (in the both most likely, and done by all modes) case
		// is that the packet is destined for another node.
		if pkt.isForward() {
			if pkt.payload != nil {
				w.log.Debugf("Dropping packet: %v (Unwrap() returned payload)", pkt.id)
				pkt.dispose()
				continue
			}
			if pkt.mustTerminate {
				w.log.Debugf("Dropping packet: %v (Provider received forward packet from mix)", pkt.id)
				pkt.dispose()
				continue
			}

			// Check and adjust the delay for queue dwell time.
			pkt.delay = time.Duration(pkt.nodeDelay.Delay) * time.Millisecond
			if pkt.delay > numMixKeys*epochtime.Period {
				w.log.Debugf("Dropping packet: %v (Delay %v is past what is possible)", pkt.id, pkt.delay)
				pkt.dispose()
				continue
			}
			dwellTime := now - pkt.recvAt
			if pkt.delay > dwellTime {
				pkt.delay -= dwellTime
			} else {
				// Eeep, the dwell time has exceeded the user requested delay.
				//
				// TODO: Either can drop or dispatch the packet immediately,
				// I'm not sure which is better behavior.
				pkt.delay = 0
			}

			// Hand off to the scheduler.
			w.log.Debugf("Dispatching packet: %v", pkt.id)
			w.s.scheduler.onPacket(pkt)
			continue
		} else if !w.s.cfg.Server.IsProvider {
			// Mixes will only ever see forward commands.
			w.log.Debugf("Dropping mix packet: %v (%v)", pkt.id, pkt.cmdsToString())
			pkt.dispose()
			continue
		}

		// This node is a provider and the packet is not destined for another
		// node.  Both of the operations here end up hitting up disk among
		// other things, so are just shunted off to a separate worker so that
		// packet processing does not get blocked.

		if pkt.mustForward {
			w.log.Debugf("Dropping client packet: %v (Send to local user)", pkt.id)
			pkt.dispose()
			continue
		}

		// Toss the packets over to the provider backend.
		// Note: Callee takes ownership of pkt.
		if pkt.isToUser() || pkt.isSURBReply() {
			w.log.Debugf("Handing off user destined packet: %v", pkt.id)
			w.s.provider.onPacket(pkt)
		} else {
			w.log.Debugf("Dropping user packet: %v (%v)", pkt.id, pkt.cmdsToString())
			pkt.dispose()
		}
	}

	// NOTREACHED
}

func (w *cryptoWorker) derefKeys() {
	for _, v := range w.mixKeys {
		v.Deref()
	}
}

func newCryptoWorker(s *Server, id int) *cryptoWorker {
	w := new(cryptoWorker)
	w.s = s
	w.log = s.logBackend.GetLogger(fmt.Sprintf("crypto:%d", id))
	w.mixKeys = make(map[uint64]*mixkey.MixKey)
	w.updateCh = make(chan bool)
	w.haltCh = make(chan interface{})
	w.Add(1)

	w.s.mixKeys.shadow(w.mixKeys)

	go w.worker()
	return w
}
