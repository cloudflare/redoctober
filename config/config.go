package config

import (
	"encoding/json"
	"io/ioutil"
)

func setIfNotEmpty(a *string, b string) {
	if b != "" {
		*a = b
	}
}

// Server contains the configuration information required to start a
// redoctober server.
type Server struct {
	// Addr contains the host:port that the server should listen
	// on.
	Addr string `json:"address"`

	// CAPath contains the path to the TLS CA for client
	// authentication. This is an optional field.
	CAPath string `json:"ca_path,omitempty"`

	// KeyPaths and CertPaths contains a list of paths to TLS key
	// pairs that should be used to secure connections to the
	// server.
	KeyPaths  []string `json:"private_keys"`
	CertPaths []string `json:"certificates"`

	// Systemd indicates whether systemd socket activation should
	// be used instead of a normal port listener.
	Systemd bool `json:"use_systemd,omitempty"`
}

// Merge copies over non-empty string values from other into the
// current Server config.
func (s *Server) Merge(other *Server) {
	setIfNotEmpty(&s.Addr, other.Addr)
	setIfNotEmpty(&s.CAPath, other.CAPath)

	if len(other.KeyPaths) != 0 {
		s.KeyPaths = other.KeyPaths
	}

	if len(other.CertPaths) != 0 {
		s.CertPaths = other.CertPaths
	}

	if other.Systemd {
		s.Systemd = true
	}
}

// UI contains the configuration information for the WWW API.
type UI struct {
	// Root contains the base URL for the UI.
	Root string `json:"root"`

	// Static is an optional path for overriding the built in HTML
	// UI.
	Static string `json:"static"`
}

// Merge copies over non-empty string values from other into the
// current UI config.
func (ui *UI) Merge(other *UI) {
	setIfNotEmpty(&ui.Root, other.Root)
	setIfNotEmpty(&ui.Static, other.Static)
}

// HipChat contains the settings for Hipchat integration.
type HipChat struct {
	Host   string `json:"host"`
	Room   string `json:"room"`
	APIKey string `json:"api_key"`
}

// Merge copies over non-empty settings from other into the current
// HipChat config.
func (hc *HipChat) Merge(other *HipChat) {
	setIfNotEmpty(&hc.Host, other.Host)
	setIfNotEmpty(&hc.Room, other.Room)
	setIfNotEmpty(&hc.APIKey, other.APIKey)
}

// Metrics contains the configuration for the Prometheus metrics
// collector.
type Metrics struct {
	Host string `json:"host"`
	Port string `json:"port"`
}

// Merge copies over non-empty settings from other into the current
// Metrics config.
func (m *Metrics) Merge(other *Metrics) {
	setIfNotEmpty(&m.Host, other.Host)
	setIfNotEmpty(&m.Port, other.Port)
}

// Delegations contains configuration for persisting delegations.
type Delegations struct {
	// Persist controls whether delegations are persisted or not.
	Persist bool `json:"persist"`

	// Policy contains the MSP predicate for delegation
	// persistence.
	Policy string `json:"policy"`
}

// Merge copies over non-empty settings from other into the current
// Delegations config.
func (d *Delegations) Merge(other *Delegations) {
	setIfNotEmpty(&d.Policy, other.Policy)

	d.Persist = d.Persist || other.Persist
}

// Config contains all the configuration options for a redoctober
// instance.
type Config struct {
	Server      *Server      `json:"server"`
	UI          *UI          `json:"ui"`
	HipChat     *HipChat     `json:"hipchat"`
	Metrics     *Metrics     `json:"metrics"`
	Delegations *Delegations `json:"delegations"`
}

// Merge copies over the non-empty settings from other into the
// current Config.
func (c *Config) Merge(other *Config) {
	c.Server.Merge(other.Server)
	c.UI.Merge(other.UI)
	c.HipChat.Merge(other.HipChat)
	c.Metrics.Merge(other.Metrics)
	c.Delegations.Merge(other.Delegations)
}

// Valid ensures that the config has enough data to start a Red
// October process.
func (c *Config) Valid() bool {
	// The RedOctober API relies on TLS for security.
	if len(c.Server.CertPaths) == 0 || len(c.Server.KeyPaths) == 0 {
		return false
	}

	// The server needs some address to listen on.
	if c.Server.Addr == "" && !c.Server.Systemd {
		return false
	}

	return true
}

// New returns a new, empty config.
func New() *Config {
	return &Config{
		Server:      &Server{},
		UI:          &UI{},
		HipChat:     &HipChat{},
		Metrics:     &Metrics{},
		Delegations: &Delegations{},
	}
}

// Load reads a JSON-encoded config file from disk.
func Load(path string) (*Config, error) {
	cfg := New()
	in, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(in, cfg)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}
