package main

import (
	"fmt"
	"os"

	"github.com/katzenpost/catshadow"
	catconfig "github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	clientConfig "github.com/katzenpost/client/config"
)

func setupCatShadow(catshadowCfg *catconfig.Config, passphrase []byte, result chan interface{}) {
	// XXX: if the catshadowClient already exists, shut it down
	// FIXME: figure out a better way to toggle connected/disconnected
	// states and allow to retry attempts on a timeout or other failure.
	if catshadowClient != nil {
		catshadowClient.Shutdown()
	}
	var stateWorker *catshadow.StateWriter
	var state *catshadow.State
	cfg, err := catshadowCfg.ClientConfig()
	if err != nil {
		result <- err
		return
	}

	// automatically create a statefile if one does not already exist
	// TODO: pick a sensible location for a default statefile other than cwd
	if _, err := os.Stat(*stateFile); os.IsNotExist(err) {
		cfg, linkKey := client.AutoRegisterRandomClient(cfg)
		c, err := client.New(cfg)
		if err != nil {
			result <- err
			return
		}

		// Create statefile.
		stateWorker, err = catshadow.NewStateWriter(c.GetLogger("catshadow_state"), *stateFile, passphrase)
		if err != nil {
			result <- err
			c.Shutdown()
			return
		}
		// Start the stateworker
		stateWorker.Start()
		fmt.Println("creating remote message receiver spool")
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			result <- err
			stateWorker.Halt()
			c.Shutdown()
			return
		}

		user := fmt.Sprintf("%x", linkKey.PublicKey().Bytes())
		catshadowClient, err = catshadow.NewClientAndRemoteSpool(backendLog, c, stateWorker, user, linkKey)
		if err != nil {
			result <- err
			stateWorker.Halt()
			c.Shutdown()
			return
		}
		fmt.Println("catshadow client successfully created")
	} else {
		cfg, _ := client.AutoRegisterRandomClient(cfg)

		// Load previous state to setup our current client state.
		backendLog, err := catshadowCfg.InitLogBackend()
		if err != nil {
			result <- err
			return
		}
		stateWorker, state, err = catshadow.LoadStateWriter(backendLog.GetLogger("state_worker"), *stateFile, passphrase)
		if err != nil {
			result <- err
			return
		}
		// Start the stateworker
		stateWorker.Start()
		cfg.Account = &clientConfig.Account{
			User:     state.User,
			Provider: state.Provider,
		}

		// Run a Client.
		c, err := client.New(cfg)
		if err != nil {
			stateWorker.Halt()
			result <- err
			return
		}

		// Make a catshadow Client.
		catshadowClient, err = catshadow.New(backendLog, c, stateWorker, state)
		if err != nil {
			c.Shutdown()
			stateWorker.Halt()
			result <- err
			return
		}
	}

	// Start catshadow client.
	catshadowClient.Start()
	result <- nil
}
