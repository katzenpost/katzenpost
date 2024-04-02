package http_proxy

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
)

// Request is the type which is serialized into the cborplugin request payload.
type Request struct {
	// Payload contains the proxied http request
	Payload []byte
}

// Response is the type which is serialized and sent as a response from the cborplugin.
type Response struct {
	// Payload contains the entire proxied http response or response chunk.
	Payload []byte

	// Error if not empty indicates an error condition.
	Error string
}

type Config struct {
	Networks map[string]string // e.g. "ethereum.mainnet" -> "https://ethereum-rpc.publicnode.com"
}

func (c *Config) Validate() error {
	for k, v := range c.Networks {
		if k == "" || v == "" {
			return errors.New("invalid entry found in config, cannot map to/from empty string")
		}
	}
	return nil
}

// Load parses and validates the provided buffer b as a config file body and
// returns the Config.
func Load(b []byte) (*Config, error) {
	if b == nil {
		return nil, errors.New("No nil buffer as config file")
	}

	cfg := new(Config)
	err := toml.Unmarshal(b, cfg)
	if err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadFile loads, parses and validates the provided file and returns the
// Config.
func LoadFile(f string) (*Config, error) {
	b, err := os.ReadFile(f)
	if err != nil {
		return nil, err
	}
	return Load(b)
}
