// survey.go - Peer connectivity survey functionality for directory authority
// Copyright (C) 2017  Yawning Angel, David Stainton.
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

package server

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	kpcommon "github.com/katzenpost/katzenpost/common"
)

// initPeerSurvey initializes the peer survey system
func (s *state) initPeerSurvey() {
	s.peerSurveyData = make(map[[publicKeyHashSize]byte]*PeerSurveyData)
	s.surveyStopCh = make(chan struct{})

	// Initialize survey data for each configured authority peer
	for _, peer := range s.s.cfg.Authorities {
		peerID := hash.Sum256From(peer.IdentityPublicKey)

		// Skip self
		if peerID == s.identityPubKeyHash() {
			continue
		}

		s.peerSurveyData[peerID] = &PeerSurveyData{
			PeerID:            peerID,
			PeerName:          peer.Identifier,
			IdentityPublicKey: peer.IdentityPublicKey,
			LinkPublicKey:     peer.LinkPublicKey,
			Addresses:         peer.Addresses,
			ConnectionHistory: make([]PeerConnectionAttempt, 0, maxSurveyHistory),
		}
	}

	// Start the survey worker
	s.surveyTicker = time.NewTicker(peerSurveyInterval)
	s.Go(s.peerSurveyWorker)
}

// peerSurveyWorker runs the periodic peer connectivity survey
func (s *state) peerSurveyWorker() {
	defer s.surveyTicker.Stop()

	s.log.Debugf("Peer survey worker started, running every %v", peerSurveyInterval)

	// Run initial survey
	s.runPeerSurvey()

	for {
		select {
		case <-s.HaltCh():
			s.log.Debugf("Peer survey worker terminating gracefully.")
			return
		case <-s.surveyStopCh:
			s.log.Debugf("Peer survey worker stopped.")
			return
		case <-s.surveyTicker.C:
			s.runPeerSurvey()
		}
	}
}

// runPeerSurvey logs peer status based on actual voting protocol interactions
func (s *state) runPeerSurvey() {
	s.Lock()
	defer s.Unlock()

	s.log.Debugf("Peer status summary based on voting protocol interactions...")
	s.logPeerSurveySummary()
}

// logPeerSurveySummary logs a concise summary of all peer connectivity status
func (s *state) logPeerSurveySummary() {
	s.log.Debugf("=== PEER SURVEY (%d peers) ===", len(s.peerSurveyData))
	for _, surveyData := range s.peerSurveyData {
		s.logPeerDetails(surveyData)
	}
	s.log.Debugf("=== END PEER SURVEY ===")
}

// stopPeerSurvey stops the peer survey worker
func (s *state) stopPeerSurvey() {
	if s.surveyTicker != nil {
		s.surveyTicker.Stop()
	}
	if s.surveyStopCh != nil {
		close(s.surveyStopCh)
	}
}

// recordConnectionAttempt records a connection attempt to/from a peer for survey tracking
func (s *state) recordConnectionAttempt(peerID [publicKeyHashSize]byte, success bool, err error, duration time.Duration, addressUsed string, direction string) {
	s.Lock()
	defer s.Unlock()

	surveyData, exists := s.peerSurveyData[peerID]
	if !exists {
		return // Unknown peer
	}

	now := time.Now()
	attempt := PeerConnectionAttempt{
		Timestamp:   now,
		Success:     success,
		Duration:    duration,
		AddressUsed: addressUsed,
		Direction:   direction,
	}

	if err != nil {
		attempt.Error = err.Error()
		attempt.ErrorCategory = s.categorizeError(err)

		// Extract additional details from wire protocol errors
		if strings.Contains(attempt.ErrorCategory, "wire_") {
			s.extractWireErrorDetails(&attempt, err)
		}
	}

	// Update connection history
	surveyData.ConnectionHistory = append(surveyData.ConnectionHistory, attempt)
	if len(surveyData.ConnectionHistory) > maxSurveyHistory {
		// Remove oldest entry
		surveyData.ConnectionHistory = surveyData.ConnectionHistory[1:]
	}

	// Update overall counters
	surveyData.TotalAttempts++
	if success {
		surveyData.SuccessfulAttempts++
		surveyData.ConsecutiveFailures = 0
		surveyData.LastSuccessfulConn = &now
	} else {
		surveyData.ConsecutiveFailures++
		surveyData.LastFailedConn = &now
	}

	// Update direction-specific counters
	if direction == "outbound" {
		surveyData.OutboundAttempts++
		if success {
			surveyData.OutboundSuccessful++
			surveyData.OutboundConsecutiveFail = 0
			surveyData.LastOutboundSuccess = &now
		} else {
			surveyData.OutboundConsecutiveFail++
			surveyData.LastOutboundFailure = &now
		}
	} else if direction == "inbound" {
		surveyData.InboundAttempts++
		if success {
			surveyData.InboundSuccessful++
			surveyData.InboundConsecutiveFail = 0
			surveyData.LastInboundSuccess = &now
		} else {
			surveyData.InboundConsecutiveFail++
			surveyData.LastInboundFailure = &now
		}
	}
}

// categorizeError categorizes connection errors for survey tracking
func (s *state) categorizeError(err error) string {
	if err == nil {
		return ""
	}

	errStr := strings.ToLower(err.Error())

	// Wire protocol specific errors (from core/wire/session.go)
	if strings.Contains(errStr, "wire/session:") {
		if strings.Contains(errStr, "handshake failed") {
			return "wire_handshake"
		}
		if strings.Contains(errStr, "protocol version mismatch") {
			return "wire_version"
		}
		if strings.Contains(errStr, "peer closed connection") {
			return "wire_disconnect"
		}
		if strings.Contains(errStr, "read timeout") || strings.Contains(errStr, "write timeout") {
			return "wire_timeout"
		}
		if strings.Contains(errStr, "invalid state") {
			return "wire_state"
		}
		if strings.Contains(errStr, "message size") {
			return "wire_msgsize"
		}
		return "wire_other"
	}

	// Network-level errors
	if strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network unreachable") ||
		strings.Contains(errStr, "dial tcp") ||
		strings.Contains(errStr, "dial udp") {
		return "network"
	}

	// Timeout errors
	if strings.Contains(errStr, "timeout") ||
		strings.Contains(errStr, "deadline exceeded") ||
		strings.Contains(errStr, "i/o timeout") {
		return "timeout"
	}

	// TLS/Handshake errors
	if strings.Contains(errStr, "handshake") ||
		strings.Contains(errStr, "tls") ||
		strings.Contains(errStr, "certificate") ||
		strings.Contains(errStr, "bad record mac") {
		return "handshake"
	}

	// Authentication errors
	if strings.Contains(errStr, "authentication") ||
		strings.Contains(errStr, "unauthorized") ||
		strings.Contains(errStr, "permission denied") {
		return "auth"
	}

	// Session/Protocol errors
	if strings.Contains(errStr, "session") ||
		strings.Contains(errStr, "protocol") {
		return "session"
	}

	return "unknown"
}

// extractWireErrorDetails extracts additional details from wire protocol errors
func (s *state) extractWireErrorDetails(attempt *PeerConnectionAttempt, err error) {
	errStr := err.Error()

	// Extract handshake state information
	if strings.Contains(errStr, "handshake failed at") {
		if start := strings.Index(errStr, "at "); start != -1 {
			if end := strings.Index(errStr[start:], " "); end != -1 {
				state := errStr[start+3 : start+end]
				attempt.Error = fmt.Sprintf("%s [state: %s]", attempt.Error, state)
			}
		}
	}

	// Extract protocol version mismatch details
	if strings.Contains(errStr, "protocol version mismatch") {
		if strings.Contains(errStr, "expected") && strings.Contains(errStr, "received") {
			// Error already contains version details, no need to modify
		}
	}

	// Extract connection details for better debugging
	if strings.Contains(errStr, "peer closed connection") {
		attempt.Error = fmt.Sprintf("%s [peer_disconnect]", attempt.Error)
	}
}

// recordIncomingConnection records an incoming connection attempt for survey tracking
func (s *state) recordIncomingConnection(peerID [publicKeyHashSize]byte, success bool, err error) {
	// For incoming connections, we don't have duration or address info
	// but we can still track success/failure
	s.recordConnectionAttempt(peerID, success, err, 0, "incoming", "inbound")
}

// logPeerDetails logs concise but comprehensive information about a specific peer
func (s *state) logPeerDetails(surveyData *PeerSurveyData) {
	// Calculate success rates
	overallRate := float64(0)
	if surveyData.TotalAttempts > 0 {
		overallRate = float64(surveyData.SuccessfulAttempts) / float64(surveyData.TotalAttempts) * 100
	}

	outboundRate := float64(0)
	if surveyData.OutboundAttempts > 0 {
		outboundRate = float64(surveyData.OutboundSuccessful) / float64(surveyData.OutboundAttempts) * 100
	}

	inboundRate := float64(0)
	if surveyData.InboundAttempts > 0 {
		inboundRate = float64(surveyData.InboundSuccessful) / float64(surveyData.InboundAttempts) * 100
	}

	// Peer header with overall connectivity stats
	s.log.Debugf("--- %s: %d/%d total (%.1f%%), %d consecutive failures",
		surveyData.PeerName,
		surveyData.SuccessfulAttempts,
		surveyData.TotalAttempts,
		overallRate,
		surveyData.ConsecutiveFailures)

	// Direction-specific stats
	s.log.Debugf("    Outbound: %d/%d (%.1f%%), %d consecutive failures",
		surveyData.OutboundSuccessful,
		surveyData.OutboundAttempts,
		outboundRate,
		surveyData.OutboundConsecutiveFail)

	s.log.Debugf("    Inbound:  %d/%d (%.1f%%), %d consecutive failures",
		surveyData.InboundSuccessful,
		surveyData.InboundAttempts,
		inboundRate,
		surveyData.InboundConsecutiveFail)

	// Addresses (compact format)
	addrs := make([]string, len(surveyData.Addresses))
	for i, addr := range surveyData.Addresses {
		if u, err := url.Parse(addr); err == nil {
			addrs[i] = fmt.Sprintf("%s://%s", u.Scheme, u.Host)
		} else {
			addrs[i] = addr
		}
	}
	s.log.Debugf("    Addresses: %s", strings.Join(addrs, ", "))

	// Last connection times (overall)
	lastSuccess := "Never"
	lastFailed := "Never"
	if surveyData.LastSuccessfulConn != nil {
		lastSuccess = surveyData.LastSuccessfulConn.Format("2006-01-02 15:04:05")
	}
	if surveyData.LastFailedConn != nil {
		lastFailed = surveyData.LastFailedConn.Format("2006-01-02 15:04:05")
	}
	s.log.Debugf("    Last success: %s | Last failure: %s", lastSuccess, lastFailed)

	// Direction-specific last connection times
	lastOutSuccess := "Never"
	lastOutFailed := "Never"
	if surveyData.LastOutboundSuccess != nil {
		lastOutSuccess = surveyData.LastOutboundSuccess.Format("15:04:05")
	}
	if surveyData.LastOutboundFailure != nil {
		lastOutFailed = surveyData.LastOutboundFailure.Format("15:04:05")
	}
	s.log.Debugf("    Last outbound: success=%s, failure=%s", lastOutSuccess, lastOutFailed)

	lastInSuccess := "Never"
	lastInFailed := "Never"
	if surveyData.LastInboundSuccess != nil {
		lastInSuccess = surveyData.LastInboundSuccess.Format("15:04:05")
	}
	if surveyData.LastInboundFailure != nil {
		lastInFailed = surveyData.LastInboundFailure.Format("15:04:05")
	}
	s.log.Debugf("    Last inbound:  success=%s, failure=%s", lastInSuccess, lastInFailed)

	// Keys (truncated)
	s.log.Debugf("    Identity: %s", kpcommon.TruncatePEMForLogging(signpem.ToPublicPEMString(surveyData.IdentityPublicKey)))
	s.log.Debugf("    Link: %s", kpcommon.TruncatePEMForLogging(kempem.ToPublicPEMString(surveyData.LinkPublicKey)))

	// Recent connection history (last 5 attempts for brevity)
	historyCount := len(surveyData.ConnectionHistory)
	if historyCount > 0 {
		s.log.Debugf("    Recent history (last %d):", min(historyCount, 5))
		start := max(0, historyCount-5)
		for i := start; i < historyCount; i++ {
			attempt := surveyData.ConnectionHistory[i]
			status := "OK"
			errorInfo := ""
			if !attempt.Success {
				status = "FAIL"
				errorInfo = fmt.Sprintf(" (%s)", attempt.ErrorCategory)
				if attempt.Error != "" {
					errorInfo += fmt.Sprintf(" - %s", attempt.Error)
				}
			}
			s.log.Debugf("      [%s] %s %s via %s (%.2fs)%s",
				attempt.Timestamp.Format("15:04:05"),
				attempt.Direction,
				status,
				attempt.AddressUsed,
				attempt.Duration.Seconds(),
				errorInfo)
		}
	} else {
		s.log.Debugf("    Recent history: No attempts recorded")
	}
}

// Helper functions for min/max
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
