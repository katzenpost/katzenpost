package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/panda/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"gopkg.in/op/go-logging.v1"
)

var log = logging.MustGetLogger("panda")
var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)

func stringToLogLevel(level string) (logging.Level, error) {
	switch level {
	case "DEBUG":
		return logging.DEBUG, nil
	case "INFO":
		return logging.INFO, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "WARNING":
		return logging.WARNING, nil
	case "ERROR":
		return logging.ERROR, nil
	case "CRITICAL":
		return logging.CRITICAL, nil
	}
	return -1, fmt.Errorf("invalid logging level %s", level)
}

func setupLoggerBackend(level logging.Level, writer io.Writer) logging.LeveledBackend {
	format := logFormat
	backend := logging.NewLogBackend(writer, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(level, "panda")
	return leveler
}

func parametersHandler(response http.ResponseWriter, req *http.Request) {
	params := new(cborplugin.Parameters)
	serialized, err := cbor.Marshal(params)
	if err != nil {
		panic(err)
	}
	_, err = response.Write(serialized)
	if err != nil {
		panic(err)
	}
}

func requestHandler(panda *server.Panda, response http.ResponseWriter, req *http.Request) {
	log.Debug("request handler")
	request := cborplugin.Request{
		Payload: make([]byte, 0),
	}
	buf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err.Error())
		panic(err)
	}
	req.Body.Close()
	err = cbor.Unmarshal(buf, &request)
	if err != nil {
		log.Error(err.Error())
		panic(err)
	}
	pandaRequestLen := binary.BigEndian.Uint32(request.Payload[:4])
	log.Debug("decoded request")
	pandaResponse, err := panda.OnRequest(request.ID, request.Payload[4:4+pandaRequestLen], request.HasSURB)
	if err != nil {
		log.Error(err.Error())
		return
	}

	// send length prefixed CBOR response
	reply := cborplugin.Response{
		Payload: pandaResponse,
	}
	serialized, err := cbor.Marshal(reply)
	if err != nil {
		log.Error(err.Error())
		panic(err)
	}
	log.Debugf("serialized response is len %d", len(serialized))
	_, err = response.Write(serialized)
	if err != nil {
		log.Error(err.Error())
		panic(err)
	}
	log.Debug("sent response")
}

func main() {
	var logLevel string
	var logDir string
	var dwellTime string
	var writeBackInterval string
	var fileStore string

	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&dwellTime, "dwell_time", "336h", "ciphertext max dwell time before garbage collection")
	flag.StringVar(&writeBackInterval, "writeBackInterval", "1h", "GC and write-back cache interval")
	flag.StringVar(&fileStore, "fileStore", "", "The file path of our on disk storage.")

	flag.Parse()

	level, err := stringToLogLevel(logLevel)
	if err != nil {
		fmt.Println("Invalid logging-level specified.")
		os.Exit(1)
	}
	if fileStore == "" {
		fmt.Println("Invalid fileStore specified.")
		os.Exit(1)
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
	logFile := path.Join(logDir, fmt.Sprintf("panda.%d.log", os.Getpid()))
	f, err := os.Create(logFile)
	logBackend := setupLoggerBackend(level, f)
	log.SetBackend(logBackend)
	log.Info("panda server started")

	dwellDuration, err := time.ParseDuration(dwellTime)
	if err != nil {
		fmt.Println("failure to parse duration string")
		os.Exit(1)
	}
	writeBackDuration, err := time.ParseDuration(writeBackInterval)
	if err != nil {
		fmt.Println("failure to parse duration string")
		os.Exit(1)
	}

	panda, err := server.New(log, fileStore, dwellDuration, writeBackDuration)
	if err != nil {
		panic(err)
	}
	_requestHandler := func(response http.ResponseWriter, request *http.Request) {
		requestHandler(panda, response, request)
	}

	server := http.Server{}
	tmpDir, err := ioutil.TempDir("", "panda_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.panda.socket", os.Getpid()))
	unixListener, err := net.Listen("unix", socketFile)
	if err != nil {
		panic(err)
	}

	http.HandleFunc("/request", _requestHandler)
	http.HandleFunc("/parameters", parametersHandler)

	fmt.Printf("%s\n", socketFile)
	defer os.Remove(socketFile)
	server.Serve(unixListener)
}
