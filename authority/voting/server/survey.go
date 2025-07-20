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

		// Log concise peer status
		s.log.Debugf("--- %s: %d/%d attempts (%.1f%%), %d consecutive failures",
			peer.PeerName, peer.SuccessfulAttempts, peer.TotalAttempts,
			successRate, peer.ConsecutiveFailures)

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
				if !attempt.Success {
					status = "FAIL"
				}
				s.log.Debugf("      [%s] %s via %s (%.2fs)",
					attempt.Timestamp.Format("15:04:05"), status,
					attempt.AddressUsed, attempt.Duration.Seconds())
			}
		}
	}

	s.log.Debugf("=== END PEER SURVEY ===")
}
