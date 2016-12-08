package config

import "testing"

func (s *Server) equal(other *Server) bool {
	if s.Addr != other.Addr {
		return false
	}

	if s.CAPath != other.CAPath {
		return false
	}

	if len(s.KeyPaths) != len(other.KeyPaths) {
		return false
	}

	if len(s.CertPaths) != len(other.KeyPaths) {
		return false
	}

	for i := range s.KeyPaths {
		if s.KeyPaths[i] != other.KeyPaths[i] {
			return false
		}
	}

	for i := range s.CertPaths {
		if s.CertPaths[i] != other.CertPaths[i] {
			return false
		}
	}

	if s.Systemd != other.Systemd {
		return false
	}

	return true
}

func (ui *UI) equal(other *UI) bool {
	if ui.Root != other.Root {
		return false
	}

	if ui.Static != other.Static {
		return false
	}

	return true
}

func (hc *HipChat) equal(other *HipChat) bool {
	if hc.Host != other.Host || hc.Room != other.Room || hc.APIKey != other.APIKey {
		return false
	}

	return true
}

func (m *Metrics) equal(other *Metrics) bool {
	return m.Host == other.Host && m.Port == other.Port
}

func (r *Reporting) equal(other *Reporting) bool {
	return r.SentryDSN == other.SentryDSN
}

func (d *Delegations) equal(other *Delegations) bool {
	return d.Persist == other.Persist && d.Policy == other.Policy
}

func (c *Config) equal(other *Config) bool {
	if !c.Server.equal(other.Server) {
		return false
	}

	if !c.UI.equal(other.UI) {
		return false
	}

	if !c.HipChat.equal(other.HipChat) {
		return false
	}

	if !c.Metrics.equal(other.Metrics) {
		return false
	}

	if !c.Reporting.equal(other.Reporting) {
		return false
	}

	if !c.Delegations.equal(other.Delegations) {
		return false
	}

	return true
}

// TestEmptyEqual makes sure two empty configurations are equal.
func TestEmptyEqual(t *testing.T) {
	a := New()
	b := New()

	if !a.equal(b) {
		t.Fatal("empty configurations should be equivalent")
	}
}

// TestLoadFile validates loading a configuration from disk.
func TestLoadFile(t *testing.T) {
	goodConfig := "testdata/config.json"
	badConfig := "testdata/bad_config.json"
	expected := New()
	expected.Server = &Server{
		Addr:      "localhost:8080",
		KeyPaths:  "testdata/server.key",
		CertPaths: "testdata/server.pem",
	}

	_, err := Load("testdata/enoent.json")
	if err == nil {
		t.Fatal("attempt to load non-existent file should fail")
	}

	_, err = Load(badConfig)
	if err == nil {
		t.Fatal("attempt to load malformed JSON should fail")
	}

	cfg, err := Load(goodConfig)
	if err != nil {
		t.Fatalf("failed to load config: %s", err)
	}

	if !cfg.equal(expected) {
		t.Fatal("loaded config is invalid")
	}
}

// TestValid validates the Validate function.
func TestValid(t *testing.T) {
	config := New()

	if config.Valid() {
		t.Fatal("empty config shouldn't be valid")
	}

	// Certs and no keys is an invalid config.
	config.Server.CertPaths = "testdata/server.pem"
	if config.Valid() {
		t.Fatal("config shouldn't be valid")
	}

	// Keys and no certs is an invalid config.
	config.Server.CertPaths = ""
	config.Server.KeyPaths = "testdata/server.key"
	if config.Valid() {
		t.Fatal("config shouldn't be valid")
	}

	// Key pairs but no address information is an invalid config.
	config.Server.CertPaths = "testdata/server.pem"
	if config.Valid() {
		t.Fatal("config shouldn't be valid")
	}

	config.Server.Addr = "localhost:8080"
	if !config.Valid() {
		t.Fatal("config should be valid")
	}

	config.Server.Addr = ""
	config.Server.Systemd = true
	if !config.Valid() {
		t.Fatal("config should be valid")
	}
}

func TestHipChatValid(t *testing.T) {
	hc := &HipChat{}
	if hc.Valid() {
		t.Fatal("empty hipchat config shouldn't be valid")
	}

	hc.APIKey = "test"
	if hc.Valid() {
		t.Fatal("invalid hipchat config shouldn't be valid")
	}

	hc.Room = "test"
	if hc.Valid() {
		t.Fatal("invalid hipchat config shouldn't be valid")
	}

	hc.Host = "test"
	if !hc.Valid() {
		t.Fatal("valid hipchat config marked as invalid")
	}
}
