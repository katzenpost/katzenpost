// SPDX-FileCopyrightText: 2017, Talek Authors
// SPDX-License-Identifier: BSD-2-Clause
//
// BSD 2-Clause License
//
// Copyright (c) 2017, Talek Authors.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	tCommon "github.com/privacylab/talek/common"
	tServer "github.com/privacylab/talek/server"
)

// generate talek replica configuration files
func (s *katzenpost) genTalekReplicaCfg(cfgPath string) {
	// write common.json
	m := rand.NewMath()
	com := tCommon.Config{
		NumBuckets:         1024,
		BucketDepth:        4,
		DataSize:           1024,
		BloomFalsePositive: .05,
		WriteInterval:      time.Second,
		ReadInterval:       time.Second,
		InterestMultiple:   10,
		InterestSeed:       int64(m.Uint64()),
		MaxLoadFactor:      0.95,
		LoadFactorStep:     0.05,
	}
	sc := tServer.Config{
		ReadBatch:     8,
		WriteInterval: time.Second,
		ReadInterval:  time.Second,
		Config:        &com,
	}

	commonDat, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		panic(err)
	}
	ioutil.WriteFile(filepath.Join(cfgPath, "common.json"), commonDat, 0640)

	// write replica.json
	// first encode
	servraw, err := json.Marshal(sc)
	if err != nil {
		fmt.Printf("Cannot flatten replica: %v\n", err)
		return
	}
	// reload both replica config and trustdomain config as JSON messages
	var servstruct map[string]interface{}
	err = json.Unmarshal(servraw, &servstruct)
	if err != nil {
		fmt.Printf("Failed to unmarshal replica: %v\n", err)
		return
	}
	delete(servstruct, "CommonConfig")
	delete(servstruct, "TrustDomain")
	tdc := *tCommon.NewTrustDomainConfig("talek", fmt.Sprintf("%s:%d", s.bindAddr, s.lastPort), true, false)
	s.lastPort += 1
	tdb, err := json.MarshalIndent(tdc, "", "  ")
	if err != nil {
		fmt.Printf("Failed to marshal trust domain: %v\n", err)
	}
	var tdstruct map[string]interface{}
	err = json.Unmarshal(tdb, &tdstruct)
	if err != nil {
		fmt.Printf("Failed to unmarshal trust domain: %v\n", err)
		return
	}
	servstruct["TrustDomain"] = tdstruct

	servraw, err = json.MarshalIndent(servstruct, "", "  ")
	if err != nil {
		fmt.Printf("Could not flatten combined replica config: %v\n", err)
		return
	}

	err = ioutil.WriteFile(filepath.Join(cfgPath, "replica.json"), servraw, 0640)
	if err != nil {
		fmt.Printf("Failed to write file: %v\n", err)
		return
	}
}
