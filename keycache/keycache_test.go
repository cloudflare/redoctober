// keycache_test.go: tests for keycache.go
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"github.com/cloudflare/redoctober/passvault"
	"testing"
	"time"
)

var now = time.Now()
var nextYear = now.AddDate(1, 0, 0)
var emptyKey = make([]byte, 16)
var dummy = make([]byte, 16)

func TestUsesFlush(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: nextYear,
			Uses:   2,
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}

	DecryptKey(dummy, "first", "", []string{}, nil)

	Refresh()
	if len(UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}
}

func TestTimeFlush(t *testing.T) {
	oneSec, _ := time.ParseDuration("1s")
	one := now.Add(oneSec)

	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: one,
			Uses:   10,
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	time.Sleep(oneSec)

	_, err := DecryptKey(dummy, "first", "", []string{}, nil)

	if err == nil {
		t.Fatalf("Error in pruning expired key")
	}
}

func TestGoodLabel(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: nextYear,
			Uses:   2,
			Labels: []string{"red"},
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	DecryptKey(dummy, "first", "", []string{"red"}, nil)

	Refresh()
	if len(UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}
}

func TestBadLabel(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: nextYear,
			Uses:   2,
			Labels: []string{"red"},
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	_, err := DecryptKey(dummy, "first", "", []string{"blue"}, nil)

	if err == nil {
		t.Fatalf("Decryption of labeled key with no permission")
	}

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}
}

func TestGoodUser(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: nextYear,
			Uses:   2,
			Users:  []string{"ci", "buildeng", "first"},
			Labels: []string{"red", "blue"},
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	DecryptKey(dummy, "first", "ci", []string{"red"}, nil)

	Refresh()
	if len(UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}
}

func TestBadUser(t *testing.T) {
	singleUse := ActiveUser{
		Admin: true,
		Type:  passvault.AESRecord,
		Usage: Usage{
			Expiry: nextYear,
			Uses:   2,
			Users:  []string{"ci", "buildeng", "first"},
			Labels: []string{"red", "blue"},
		},
		aesKey: emptyKey,
	}

	UserKeys["first"] = singleUse

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	// Note that the active user needs to be in the set of delegated
	// users in the AES case only
	EncryptKey(dummy, "first", nil)

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	_, err := DecryptKey(dummy, "first", "", []string{"blue"}, nil)

	if err == nil {
		t.Fatalf("Decryption of labeled key by unauthorized user")
	}

	Refresh()
	if len(UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", UserKeys)
	}
}
