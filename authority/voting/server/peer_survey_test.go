package server

import (
	"fmt"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func TestPeerSurveyDataStructures(t *testing.T) {
	// Test that our data structures work correctly
	kemScheme := schemes.ByName("X25519")
	require.NotNil(t, kemScheme)

	signScheme := signSchemes.ByName("Ed25519")
	require.NotNil(t, signScheme)

	// Create test keys
	identityPub, _, err := signScheme.GenerateKey()
	require.NoError(t, err)

	linkPub, _, err := kemScheme.GenerateKeyPair()
	require.NoError(t, err)

	peerID := hash.Sum256From(identityPub)

	// Create survey data
	surveyData := &PeerSurveyData{
		PeerID:            peerID,
		PeerName:          "test-authority",
		IdentityPublicKey: identityPub,
		LinkPublicKey:     linkPub,
		Addresses:         []string{"tcp://127.0.0.1:29483", "quic://127.0.0.1:29484"},
		ConnectionHistory: make([]PeerConnectionAttempt, 0, maxSurveyHistory),
	}

	// Test recording connection attempts
	now := time.Now()

	// Record a successful attempt
	attempt1 := PeerConnectionAttempt{
		Timestamp:     now,
		Success:       true,
		Error:         "",
		Duration:      100 * time.Millisecond,
		AddressUsed:   "tcp://127.0.0.1:29483",
		ErrorCategory: "",
	}

	surveyData.ConnectionHistory = append(surveyData.ConnectionHistory, attempt1)
	surveyData.TotalAttempts++
	surveyData.SuccessfulAttempts++
	surveyData.LastSuccessfulConn = &now

	// Record a failed attempt
	failTime := now.Add(5 * time.Minute)
	attempt2 := PeerConnectionAttempt{
		Timestamp:     failTime,
		Success:       false,
		Error:         "connection refused",
		Duration:      30 * time.Second,
		AddressUsed:   "tcp://127.0.0.1:29483",
		ErrorCategory: "network",
	}

	surveyData.ConnectionHistory = append(surveyData.ConnectionHistory, attempt2)
	surveyData.TotalAttempts++
	surveyData.ConsecutiveFailures++
	surveyData.LastFailedConn = &failTime

	// Verify statistics
	require.Equal(t, 2, surveyData.TotalAttempts)
	require.Equal(t, 1, surveyData.SuccessfulAttempts)
	require.Equal(t, 1, surveyData.ConsecutiveFailures)
	require.NotNil(t, surveyData.LastSuccessfulConn)
	require.NotNil(t, surveyData.LastFailedConn)
	require.Equal(t, 2, len(surveyData.ConnectionHistory))
}

func TestErrorCategorization(t *testing.T) {
	// Create a minimal state for testing
	st := &state{}

	testCases := []struct {
		error    string
		expected string
	}{
		{"dial tcp: connection refused", "network"},
		{"context deadline exceeded", "timeout"},
		{"handshake failed", "handshake"},
		{"tls: bad certificate", "handshake"},
		{"authentication failed", "auth"},
		{"session creation failed", "session"},
		{"some unknown error", "unknown"},
	}

	for _, tc := range testCases {
		t.Run(tc.error, func(t *testing.T) {
			category := st.categorizeError(fmt.Errorf("%s", tc.error))
			require.Equal(t, tc.expected, category)
		})
	}
}

func TestHistoryTrimming(t *testing.T) {
	surveyData := &PeerSurveyData{
		ConnectionHistory: make([]PeerConnectionAttempt, 0, maxSurveyHistory),
	}

	// Add more than maxSurveyHistory attempts
	for i := 0; i < maxSurveyHistory+10; i++ {
		attempt := PeerConnectionAttempt{
			Timestamp: time.Now().Add(time.Duration(i) * time.Minute),
			Success:   i%2 == 0, // Alternate success/failure
		}

		surveyData.ConnectionHistory = append(surveyData.ConnectionHistory, attempt)

		// Trim if necessary
		if len(surveyData.ConnectionHistory) > maxSurveyHistory {
			surveyData.ConnectionHistory = surveyData.ConnectionHistory[1:]
		}
	}

	// Should not exceed maxSurveyHistory
	require.Equal(t, maxSurveyHistory, len(surveyData.ConnectionHistory))

	// Should contain the most recent attempts
	lastAttempt := surveyData.ConnectionHistory[len(surveyData.ConnectionHistory)-1]
	require.True(t, lastAttempt.Timestamp.After(surveyData.ConnectionHistory[0].Timestamp))
}
