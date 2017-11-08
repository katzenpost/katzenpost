// http_handler.go - Katzenpost non-voting authority HTTP handler.
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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/katzenpost/authority/nonvoting/internal/constants"
	"github.com/katzenpost/authority/nonvoting/internal/s11n"
	"github.com/katzenpost/core/epochtime"
)

func (s *Server) logInvalidRequest(req *http.Request, err error) {
	if err != nil {
		s.log.Errorf("Peer %v: %v Invalid request: '%v' (%v)", req.RemoteAddr, req.Method, req.URL, err)
		return
	}
	s.log.Errorf("Peer %v: %v Invalid request: '%v'", req.RemoteAddr, req.Method, req.URL)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.Add(1)
	defer s.Done()

	s.log.Debugf("Peer %v: %v Request: '%v'", req.RemoteAddr, req.Method, req.URL)
	setCacheControl(w) // Disable response caching by default.

	// Figure out if this is a document download or a descriptor upload.
	p := req.URL.Path
	if strings.HasPrefix(p, constants.V0GetBase) {
		s.onV0Get(w, req)
	} else if strings.HasPrefix(p, constants.V0PostBase) {
		s.onV0Post(w, req)
	} else {
		s.logInvalidRequest(req, nil)
		http.Error(w, "invalid URL", http.StatusBadRequest)
	}
}

func (s *Server) onV0Get(w http.ResponseWriter, req *http.Request) {
	// Validate the HTTP method, and extract the epoch.
	if req.Method != http.MethodGet {
		s.logInvalidRequest(req, nil)
		http.Error(w, "invalid HTTP method for URL", http.StatusBadRequest)
		return
	}
	epoch, err := extractEpoch(req.URL.Path, constants.V0GetBase)
	if err != nil {
		s.logInvalidRequest(req, err)
		http.Error(w, "failed to parse epoch", http.StatusBadRequest)
		return
	}

	// Look up the document for the requested epoch.
	doc, err := s.state.documentForEpoch(epoch)
	if err != nil {
		s.logInvalidRequest(req, err)
		switch err {
		case errGone:
			http.Error(w, "requested epoch too far in the past", http.StatusGone)
		case errNotYet:
			http.Error(w, "document not ready yet", http.StatusInternalServerError)
		default:
			// No idea what epoch the client is asking for, their clock is
			// probably way off.
			http.NotFound(w, req)
		}
		return
	}

	// Serve the response.
	s.log.Debugf("Peer: %v: Serving document for epoch %v.", req.RemoteAddr, epoch)
	unsetCacheControl(w) // This can be cached.
	w.Header().Set("Content-Type", constants.JoseMIMEType)
	r := bytes.NewReader(doc)
	http.ServeContent(w, req, "", time.Time{}, r)
}

func (s *Server) onV0Post(w http.ResponseWriter, req *http.Request) {
	const maxDescriptorSize = 4096 // 4 KiB is more than enough.

	// Validate the HTTP method, and extract the epoch.
	if req.Method != http.MethodPost {
		s.logInvalidRequest(req, nil)
		http.Error(w, "invalid HTTP method for URL", http.StatusBadRequest)
		return
	}
	descEpoch, err := extractEpoch(req.URL.Path, constants.V0PostBase)
	if err != nil {
		s.logInvalidRequest(req, err)
		http.Error(w, "failed to parse epoch", http.StatusBadRequest)
		return
	}

	// Ensure the epoch is somewhat sane.
	now, _, _ := epochtime.Now()
	switch descEpoch {
	case now - 1, now, now + 1:
		// Nodes will always publish the descriptor for the current epoch on
		// launch, which may be off by one period, depending on how skewed
		// the node's clock is and the current time.
	default:
		// The peer is publishing for an epoch that's invalid.
		s.logInvalidRequest(req, fmt.Errorf("invalid epoch %v", descEpoch))
		http.Error(w, "invalid epoch", http.StatusBadRequest)
		return
	}

	// Read the body.
	r := http.MaxBytesReader(w, req.Body, maxDescriptorSize)
	b, err := ioutil.ReadAll(r)
	if err != nil {
		// The MaxBytesReader handles sending a response.
		s.logInvalidRequest(req, err)
		return
	}

	// Validate and deserialize the descriptor.
	desc, err := s11n.VerifyAndParseDescriptor(b, descEpoch)
	if err != nil {
		s.logInvalidRequest(req, err)
		http.Error(w, "invalid descriptor", http.StatusBadRequest)
		return
	}

	// Ensure that the descriptor is from an allowed peer.
	if !s.state.isDescriptorAuthorized(desc) {
		s.logInvalidRequest(req, fmt.Errorf("identity key '%v' not authorized", desc.IdentityKey))
		http.Error(w, "public key not recognized", http.StatusForbidden)
		return
	}

	// Hand the descriptor off to the state worker.  As long as this returns
	// a nil, the authority "accepts" the descriptor.
	err = s.state.onDescriptorUpload(b, desc, descEpoch)
	if err != nil {
		// This is either a internal server error or the peer is trying to
		// retroactively modify their descriptor.  This should disambituate
		// the condition, but the latter is more likely.
		s.logInvalidRequest(req, err)
		http.Error(w, "rejected, conflicting upload?", http.StatusConflict)
		return
	}

	// Return a successful response.
	s.log.Debugf("Peer %v: Accepted descriptor for epoch %v: '%v'", req.RemoteAddr, descEpoch, desc)
	http.Error(w, "", http.StatusAccepted)
}

func extractEpoch(s, prefix string) (uint64, error) {
	es := strings.TrimPrefix(s, prefix)
	return strconv.ParseUint(es, 10, 64)
}

func setCacheControl(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
}

func unsetCacheControl(w http.ResponseWriter) {
	w.Header().Del("Cache-Control")
}
