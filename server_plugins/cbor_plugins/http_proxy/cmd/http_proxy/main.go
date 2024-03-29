package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server_plugins/cbor_plugins/http_proxy"
)

const MaxPayloadSize = 15000 - 20

func main() {
	var logLevel string
	var logDir string
	var destURL string

	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&destURL, "dest_url", "", "destination URL for reverse proxying to")
	flag.Parse()

	if destURL == "" {
		panic("proxy destination must be set")
	}
	myurl, err := url.Parse(destURL)
	if err != nil {
		panic(err)
	}

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("http_proxy.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("http_proxy")

	// start service
	tmpDir, err := os.MkdirTemp("", "http_proxy")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.http_proxy.socket", os.Getpid()))

	var server *cborplugin.Server

	h := New(serverLog, myurl)
	server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestFactory), h)

	// emit socketFile to stdout, because this tells the mix server where to connect
	fmt.Printf("%s\n", socketFile)

	server.Accept()
	server.Wait()

	os.Remove(socketFile)
}

type proxyRequestHandler struct {
	log  *logging.Logger
	dest *url.URL
}

func New(log *logging.Logger, dest *url.URL) *proxyRequestHandler {
	return &proxyRequestHandler{
		log:  log,
		dest: dest,
	}
}

// OnCommand processes a SpoolRequest and returns a SpoolResponse
func (s *proxyRequestHandler) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	s.log.Info("OnCommand begin")
	defer s.log.Info("OnCommand end")

	switch r := cmd.(type) {
	case *cborplugin.Request:
		// the padding bytes were not stripped because
		// without parsing the start of Payload we wont
		// know how long it is, so we will use a streaming
		// decoder and simply return the first cbor object
		// and then discard the decoder and buffer
		req := &http_proxy.Request{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			s.log.Errorf("dec.Decode(req) failed: %s", err)
			return nil, err
		}

		s.log.Debugf("Raw request payload: %s", req.Payload)

		request, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(req.Payload)))
		if err != nil {
			s.log.Errorf("http.ReadRequest failed: %s", err)
			return nil, fmt.Errorf("http.ReadRequest failed: %s", err)
		}

		newRequest, err := http.NewRequest(request.Method, s.dest.String(), request.Body)
		if err != nil {
			s.log.Errorf("http.NewRequest failed: %s", err)
			return nil, fmt.Errorf("http.NewRequest failed: %s", err)
		}

		newRequest.Header.Set("Content-Type", request.Header.Get("Content-Type"))
		newRequest.Header.Set("Content-Length", request.Header.Get("Content-Length"))

		resp, err := http.DefaultClient.Do(newRequest)
		if err != nil {
			s.log.Errorf("http.DefaultClient.Do failed: %s", err)
			return nil, fmt.Errorf("http.DefaultClient.Do failed: %s", err)
		}
		defer resp.Body.Close()

		resp.Header["Host"] = []string{request.URL.Host}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			s.log.Errorf("io.ReadAll(resp.Body) failed: %s", err)
			return nil, fmt.Errorf("io.ReadAll(resp.Body) failed: %s", err)
		}

		s.log.Debugf("Reply payload: %s", body)

		var response *http_proxy.Response
		if len(body) > MaxPayloadSize {
			s.log.Error("http response body exceeds max Sphinx payload")
			response = &http_proxy.Response{
				Error: "http response is too big",
			}
		} else {
			response = &http_proxy.Response{
				Payload: body,
			}
		}

		payload, err := cbor.Marshal(response)
		if err != nil {
			s.log.Errorf("cbor.Marshal(response) failed: %s", err)
			return nil, fmt.Errorf("cbor.Marshal(response) failed: %s", err)
		}

		return &cborplugin.Response{Payload: payload}, nil
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("Invalid Command type")
	}
}

// RegisterConsumer is required by our plugin system interface
func (s *proxyRequestHandler) RegisterConsumer(svr *cborplugin.Server) {}
