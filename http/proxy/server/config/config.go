package config

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type Config struct {
	SphinxGeometry *geo.Geometry
}

func (c *Config) Validate() error {
	if c.SphinxGeometry == nil {
		return errors.New("config: No SphinxGeometry block was present")
	}
	err := c.SphinxGeometry.Validate()
	if err != nil {
		return err
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
