// survey.go - Minimal peer connectivity survey functionality for directory authority

package server

import (
	"fmt"

	"github.com/katzenpost/hpqc/hash"
)

// runPeerSurvey logs peer status based on actual voting protocol interactions
func (s *state) runPeerSurvey() {
	s.Lock()
	defer s.Unlock()

	s.logPeerSurveySummary()
}

// logPeerSurveySummary logs a concise summary of all peer connectivity status
func (s *state) logPeerSurveySummary() {
	s.log.Debugf("=== PEER SURVEY (%d peers) ===", len(s.peerSurveyData))

	// Log directory authority peers
	for peerID, peer := range s.peerSurveyData {
		if peer.PeerName == "" {
			// Try to find peer name from config
			for _, auth := range s.s.cfg.Authorities {
				if hash.Sum256From(auth.IdentityPublicKey) == peerID {
					peer.PeerName = auth.Identifier
					break
				}
			}
			if peer.PeerName == "" {
				peer.PeerName = fmt.Sprintf("peer-%x", peerID[:8])
			}
		}

		// Calculate success rate
		successRate := 0.0
		if peer.TotalAttempts > 0 {
			successRate = float64(peer.SuccessfulAttempts) / float64(peer.TotalAttempts) * 100.0
		}

		// Format last success/failure times
		lastSuccess := "Never"
		if peer.LastSuccessfulConn != nil {
			lastSuccess = peer.LastSuccessfulConn.Format("15:04:05")
		}

		lastFailure := "Never"
		if peer.LastFailedConn != nil {
			lastFailure = peer.LastFailedConn.Format("15:04:05")
		}

		// Separate incoming vs outgoing connections
		incomingCount := 0
		outgoingCount := 0
		incomingSuccess := 0
		outgoingSuccess := 0

		for _, attempt := range peer.ConnectionHistory {
			if attempt.Duration == 0 {
				// Incoming connection (duration is 0)
				incomingCount++
				if attempt.Success {
					incomingSuccess++
				}
			} else {
				// Outgoing connection (has duration)
				outgoingCount++
				if attempt.Success {
					outgoingSuccess++
				}
			}
		}

		// Log concise peer status with incoming/outgoing breakdown
		s.log.Debugf("--- %s: %d/%d total (%.1f%%), %d consecutive failures",
			peer.PeerName, peer.SuccessfulAttempts, peer.TotalAttempts,
			successRate, peer.ConsecutiveFailures)

		if incomingCount > 0 || outgoingCount > 0 {
			incomingRate := 0.0
			if incomingCount > 0 {
				incomingRate = float64(incomingSuccess) / float64(incomingCount) * 100.0
			}
			outgoingRate := 0.0
			if outgoingCount > 0 {
				outgoingRate = float64(outgoingSuccess) / float64(outgoingCount) * 100.0
			}
			s.log.Debugf("    Incoming: %d/%d (%.1f%%) | Outgoing: %d/%d (%.1f%%)",
				incomingSuccess, incomingCount, incomingRate,
				outgoingSuccess, outgoingCount, outgoingRate)
		}

		if len(peer.Addresses) > 0 {
			s.log.Debugf("    Addresses: %v", peer.Addresses)
		}

		s.log.Debugf("    Last success: %s | Last failure: %s", lastSuccess, lastFailure)

		// Show recent connection history (last 5 attempts)
		historyCount := len(peer.ConnectionHistory)
		if historyCount > 0 {
			s.log.Debugf("    Recent history (last %d):", min(historyCount, 5))
			start := 0
			if historyCount > 5 {
				start = historyCount - 5
			}
			for i := start; i < historyCount; i++ {
				attempt := peer.ConnectionHistory[i]
				status := "OK"
				direction := "IN"
				if !attempt.Success {
					status = "FAIL"
				}
				if attempt.Duration > 0 {
					direction = "OUT"
				}
				errorInfo := ""
				if !attempt.Success {
					if attempt.ErrorCategory != "" {
						errorInfo = fmt.Sprintf(" (%s)", attempt.ErrorCategory)
					}
					if attempt.Error != "" {
						errorInfo += fmt.Sprintf(" - %s", attempt.Error)
					}
				}
				s.log.Debugf("      [%s] %s %s via %s (%.2fs)%s",
					attempt.Timestamp.Format("15:04:05"), direction, status,
					attempt.AddressUsed, attempt.Duration.Seconds(), errorInfo)
			}
		}
	}

	s.log.Debugf("=== END PEER SURVEY ===")
}
