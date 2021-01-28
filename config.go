package main

import (
	"log"
	"os"

	"github.com/BurntSushi/toml"
)

// Config holds catchat's config settings
type Config struct {
	Theme        string
	Style        string
	Notification string
	PositionX    int
	PositionY    int
	Width        int
	Height       int
	FirstRun     bool
}

// LoadConfig returns the current config as a Config struct
func LoadConfig(configFile string) Config {
	_, err := os.Stat(configFile)
	if err != nil {
		SaveConfig(configFile, Config{
			Theme:        "Material",
			Style:        "Dark",
			Notification: "Full",
			FirstRun:     true,
		})
		//log.Fatal("Config file is missing, but a template was created for you! Please edit ", configFile)
	}

	var config Config
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		log.Fatal("Could not decode config file: ", err)
	}

	if config.Theme == "" {
		config.Theme = "Material"
	}
	if config.Style == "" {
		config.Style = "Dark"
	}
	if config.Notification == "" {
		config.Notification = "Full"
	}

	return config
}

// SaveConfig stores the current config
func SaveConfig(configFile string, config Config) {
	f, err := os.Create(configFile)
	if err != nil {
		log.Fatal("Could not open config file: ", err)
	}
	if err := toml.NewEncoder(f).Encode(config); err != nil {
		log.Fatal("Could not encode config: ", err)
	}
}
