package genconfig

import (
	"log"
	"os"
	"path/filepath"
)

func (s *Katzenpost) GenPrometheus() error {
	dest := filepath.Join(s.OutDir, "prometheus.yml")
	log.Printf("writing %s", dest)

	f, err := os.Create(dest)

	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	write(f, `
scrape_configs:
- job_name: katzenpost
  scrape_interval: 1s
  static_configs:
  - targets:
`)

	for _, cfg := range s.NodeConfigs {
		write(f, `    - %s
`, cfg.Server.MetricsAddress)
	}
	return nil
}
