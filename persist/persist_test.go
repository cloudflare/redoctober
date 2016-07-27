package persist

import (
	"testing"

	"github.com/cloudflare/redoctober/config"
)

func TestNew(t *testing.T) {
	cfg := &config.Delegations{
		Persist:   true,
		Policy:    "policy",
		Users:     []string{"alice"},
		Mechanism: FileMechanism,
		Location:  "testdata/store.bin",
	}

	store, err := New(cfg)
	if err != nil {
		t.Fatalf("persist: failed to create a new store: %s", err)
	}

	if _, ok := store.(*File); !ok {
		t.Fatalf("persist: New should return a *File, but returned a %T", store)
	}
}
