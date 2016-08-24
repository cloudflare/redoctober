package persist

import (
	"testing"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/passvault"
)

func TestNewNull(t *testing.T) {
	cfg := &config.Delegations{
		Persist:   false,
		Mechanism: FileMechanism,
		Location:  "testdata/store.bin",
		Policy:    "policy",
	}

	store, err := New(cfg)
	if err != nil {
		t.Fatalf("persist: failed to create a new store: %s", err)
	}

	if _, ok := store.(*Null); !ok {
		t.Fatalf("persist: expected a Null store, but have %T", store)
	}

	if store.Blob() != nil {
		t.Fatalf("persist: Null store should return an empty blob")
	}

	if store.Policy() != cfg.Policy {
		t.Fatalf("persist: expected a consistent policy")
	}

	if err := store.Store([]byte("test data")); err != nil {
		t.Fatalf("persist: Null.Store failed with %s", err)
	}

	if err := store.Load(); err != nil {
		t.Fatalf("persist: Null.Load failed with %s", err)
	}

	status := store.Status()
	if status.State != Disabled {
		t.Fatalf("persist: Null store should never persist")
	}

	if len(status.Summary) != 0 {
		t.Fatal("persist: Null summary should have zero entries")
	}

	err = store.Delegate(passvault.PasswordRecord{}, "name", "password", []string{}, []string{}, 1, "", "1h")
	if err == nil {
		t.Fatal("persist: expected delegation to fail")
	}

	if cache := store.Cache(); len(cache.UserKeys) != 0 {
		t.Fatal("persist: Null Cache() should return an empty cache")
	}

	if store.Purge() != nil {
		t.Fatal("persist: Null Purge() shouldn't return an error")
	}
}
