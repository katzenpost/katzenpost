// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"log"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	vConfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	cConfig "github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/genconfig"
)

const (
	basePort       = 30000
	bindAddr       = "127.0.0.1"
	nrLayers       = 3
	nrNodes        = 6
	nrGateways     = 1
	nrServiceNodes = 1
	nrAuthorities  = 3
)

func main() {
	nrLayers := flag.Int("L", nrLayers, "Number of layers.")
	nrNodes := flag.Int("n", nrNodes, "Number of mixes.")

	nrGateways := flag.Int("gateways", nrGateways, "Number of gateways.")
	nrServiceNodes := flag.Int("serviceNodes", nrServiceNodes, "Number of providers.")

	nrVoting := flag.Int("nv", nrAuthorities, "Generate voting configuration")
	baseDir := flag.String("b", "", "Path to use as baseDir option")
	basePort := flag.Int("P", basePort, "First port number to use")
	bindAddr := flag.String("a", bindAddr, "Address to bind to")
	outDir := flag.String("o", "", "Path to write files to")
	dockerImage := flag.String("d", "katzenpost-go_mod", "Docker image for compose-compose")
	binSuffix := flag.String("S", "", "suffix for binaries in docker-compose.yml")
	logLevel := flag.String("log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	omitTopology := flag.Bool("D", false, "Dynamic topology (omit fixed topology definition)")
	wirekem := flag.String("wirekem", "", "Name of the KEM Scheme to be used with wire protocol")
	kem := flag.String("kem", "", "Name of the KEM Scheme to be used with Sphinx")
	nike := flag.String("nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")
	ratchetNike := flag.String("ratchetNike", "CTIDH512-X25519", "Name of the NIKE Scheme to be used with the doubleratchet")
	UserForwardPayloadLength := flag.Int("UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	pkiSignatureScheme := flag.String("pkiScheme", "Ed25519", "PKI Signature Scheme to be used")
	noDecoy := flag.Bool("noDecoy", true, "Disable decoy traffic for the client")
	noMixDecoy := flag.Bool("noMixDecoy", true, "Disable decoy traffic for the mixes")
	dialTimeout := flag.Int("dialTimeout", 0, "Session dial timeout")
	maxPKIDelay := flag.Int("maxPKIDelay", 0, "Initial maximum PKI retrieval delay")
	pollingIntvl := flag.Int("pollingIntvl", 0, "Polling interval")

	sr := flag.Uint64("sr", 0, "Sendrate limit")
	mu := flag.Float64("mu", 0.005, "Inverse of mean of per hop delay.")
	muMax := flag.Uint64("muMax", 1000, "Maximum delay for Mu.")
	lP := flag.Float64("lP", 0.001, "Inverse of mean for client send rate LambdaP")
	lPMax := flag.Uint64("lPMax", 1000, "Maximum delay for LambdaP.")
	lL := flag.Float64("lL", 0.0005, "Inverse of mean of loop decoy send rate LambdaL")
	lLMax := flag.Uint64("lLMax", 1000, "Maximum delay for LambdaL")
	lD := flag.Float64("lD", 0.0005, "Inverse of mean of drop decoy send rate LambdaD")
	lDMax := flag.Uint64("lDMax", 3000, "Maximum delay for LambaD")
	lM := flag.Float64("lM", 0.2, "Inverse of mean of mix decoy send rate")
	lMMax := flag.Uint64("lMMax", 100, "Maximum delay for LambdaM")
	lGMax := flag.Uint64("lGMax", 100, "Maximum delay for LambdaM")

	flag.Parse()

	if *wirekem == "" {
		log.Fatal("wire KEM must be set")
	}

	if *kem == "" && *nike == "" {
		log.Fatal("either nike or kem must be set")
	}
	if *kem != "" && *nike != "" {
		log.Fatal("nike and kem flags cannot both be set")
	}

	if *ratchetNike == "" {
		log.Fatal("ratchetNike must be set")
	}

	s := &genconfig.Katzenpost{}
	s.Parameters = &vConfig.Parameters{
		SendRatePerMinute: *sr,
		Mu:                *mu,
		MuMaxDelay:        *muMax,
		LambdaP:           *lP,
		LambdaPMaxDelay:   *lPMax,
		LambdaL:           *lL,
		LambdaLMaxDelay:   *lLMax,
		LambdaD:           *lD,
		LambdaDMaxDelay:   *lDMax,
		LambdaM:           *lM,
		LambdaMMaxDelay:   *lMMax,
		LambdaGMaxDelay:   *lGMax,
	}
	s.NumMixes = *nrNodes
	s.NumGateways = *nrGateways
	s.NumServiceNodes = *nrServiceNodes
	s.NumVoting = *nrVoting
	s.NumLayers = *nrLayers

	s.RatchetNIKEScheme = *ratchetNike

	s.WireKEMScheme = *wirekem
	if kemschemes.ByName(*wirekem) == nil {
		log.Fatal("invalid wire KEM scheme")
	}

	s.DockerImageName = *dockerImage
	s.OmitTopology = *omitTopology
	s.BaseDir = *baseDir
	s.OutDir = *outDir
	s.BinSuffix = *binSuffix
	s.BasePort = uint16(*basePort)
	s.LastPort = s.BasePort + 1
	s.BindAddr = *bindAddr
	s.LogLevel = *logLevel
	s.DebugConfig = &cConfig.Debug{
		DisableDecoyTraffic:         *noDecoy,
		SessionDialTimeout:          *dialTimeout,
		InitialMaxPKIRetrievalDelay: *maxPKIDelay,
		PollingInterval:             *pollingIntvl,
	}
	s.NoMixDecoy = *noMixDecoy

	nrHops := *nrLayers + 2

	if *nike != "" {
		nikeScheme := schemes.ByName(*nike)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", *nike)
		}
		s.SphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *kem != "" {
		kemScheme := kemschemes.ByName(*kem)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", *kem)
		}
		s.SphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *pkiSignatureScheme != "" {
		signScheme := signSchemes.ByName(*pkiSignatureScheme)
		if signScheme == nil {
			log.Fatalf("failed to resolve pki signature scheme %s", *pkiSignatureScheme)
		}
		s.PKISignatureScheme = signScheme
	}
}
