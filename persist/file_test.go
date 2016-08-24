package persist

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/redoctober/config"
)

func fexists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func TestFileConfig(t *testing.T) {
	cfg := &config.Delegations{
		Persist: false,
	}
	f := &File{config: cfg}

	if f.Valid() {
		t.Fatal("persist: File config should persist")
	}

	cfg.Persist = true
	if f.Valid() {
		t.Fatal("persist: File config should require policy")
	}

	cfg.Policy = "some policy"
	if f.Valid() {
		t.Fatal("persist: File config should require mechanism")
	}

	cfg.Users = []string{"alice", "bob"}

	cfg.Mechanism = "db"
	if f.Valid() {
		t.Fatalf("persist: File config should require the '%s' mechanism", FileMechanism)
	}

	cfg.Mechanism = FileMechanism
	if f.Valid() {
		t.Fatal("persist: File config should require a location")
	}

	cfg.Location = "testdata/store.bin"
	if !f.Valid() {
		t.Fatal("persist: valid File config marked as invalid")
	}

	cfg.Location = ""
	_, err := New(cfg)
	if err != ErrInvalidConfig {
		t.Fatalf("persist: expected err='%s', have err='%s'",
			ErrInvalidConfig, err)
	}
}

func tempName() (string, error) {
	tmpf, err := ioutil.TempFile("", "transport_cachedkp_")
	if err != nil {
		return "", err
	}

	name := tmpf.Name()
	tmpf.Close()
	return name, nil
}

func TestFileSanity(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	const expected = "testdata"
	err = ioutil.WriteFile(sf, []byte(expected), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if string(f.Blob()) != expected {
		t.Fatalf("persist: expected blob data '%s' but have '%s'", expected, f.Blob())
	}

	if f.Policy() != cfg.Policy {
		t.Fatalf("persist: policy mismatch - should have '%s' but have '%s'",
			cfg.Policy, f.Policy())
	}

	if len(f.Users()) != 2 {
		t.Fatalf("persist: expected 2 users, have %d", len(f.Users()))
	}

	const expected2 = "test data"
	if err = f.Store([]byte(expected2)); err != nil {
		t.Fatal(err)
	}

	if string(f.Blob()) == expected2 {
		t.Fatal("persist: should not have begun persisting yet")
	}

	f.Persist()
	if err = f.Store([]byte(expected2)); err != nil {
		t.Fatal(err)
	}

	if string(f.Blob()) != expected2 {
		t.Fatalf("persist: expected blob data '%s' but have '%s'", expected2, f.Blob())
	}

	err = ioutil.WriteFile(sf, []byte(expected), 0644)
	if err != nil {
		t.Fatal(err)
	}

	if err = f.Load(); err != nil {
		t.Fatal(err)
	}

	if string(f.Blob()) != expected {
		t.Fatalf("persist: expected blob data '%s' but have '%s'", expected2, f.Blob())
	}

}

func TestNewFilePersists(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	file, ok := f.(*File)
	if !ok {
		t.Fatalf("persist: expected to get a *File but have %T", f)
	}

	if file.state != Active {
		t.Fatalf("fresh store should be persisting")
	}
}

func TestActivePurge(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	_, ok := f.(*File)
	if !ok {
		t.Fatalf("persist: expected to get a *File but have %T", f)
	}

	const expected = "test data"
	if err = f.Store([]byte(expected)); err != nil {
		t.Fatal(err)
	}

	if !fexists(sf) {
		t.Fatalf("persist: file store wasn't written to disk")
	}

	err = f.Purge()
	if err != nil {
		t.Fatalf("%s", err)
	}

	if fexists(sf) {
		t.Fatalf("persist: store should have been removed during purge")
	}
}

func TestInactivePurge(t *testing.T) {
	sf, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(sf)

	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: FileMechanism,
		Policy:    "alice & bob",
		Users:     []string{"alice", "bob"},
		Location:  sf,
	}

	const expected = "test data"
	err = ioutil.WriteFile(sf, []byte(expected), 0644)
	if err != nil {
		t.Fatalf("%s", err)
	}

	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	file, ok := f.(*File)
	if !ok {
		t.Fatalf("persist: expected to get a *File but have %T", f)
	}

	if err = f.Store([]byte(expected)); err != nil {
		t.Fatal(err)
	}

	err = f.Purge()
	if err != nil {
		t.Fatalf("%s", err)
	}

	if fexists(sf) {
		t.Fatalf("persist: store should have been removed during purge")
	}

	if file.Status().State != Active {
		t.Fatalf("fresh store should be persisting")
	}
}
