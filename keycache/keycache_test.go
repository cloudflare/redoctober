// keycache_test.go: tests for keycache.go
//
// Copyright (c) 2013 CloudFlare, Inc.
package keycache

import (
	"bytes"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/symcrypt"
)

func TestUsesFlush(t *testing.T) {
	// Initialize passvault with one dummy user.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	// Initialize keycache and delegate the user's key to it.
	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", "", &Usage{2, nil, []string{"alice"}, time.Now().Add(duration), false})
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	// Generate a random symmetric key, encrypt a blank block with it, and encrypt
	// the key itself with the user's public key.
	dummy := make([]byte, 16)
	key, err := symcrypt.MakeRandom(16)
	if err != nil {
		t.Fatalf("%v", err)
	}

	encKey, err := symcrypt.EncryptCBC(dummy, dummy, key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	pubEncryptedKey, err := pr.EncryptKey(key)
	if err != nil {
		t.Fatalf("%v", err)
	}

	key2, err := cache.DecryptKey(encKey, "user", "anybody", []string{}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if bytes.Equal(key, key2) {
		t.Fatalf("cache.DecryptKey didnt decrypt the right key!")
	}

	// Second decryption allowed.
	_, err = cache.DecryptKey(encKey, "user", "anybody else", []string{}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestTimeFlush(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key for 1s, wait a
	// second and then make sure that it's gone.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1s")
	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", "", &Usage{10, nil, []string{"alice"}, time.Now().Add(duration), false})
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	time.Sleep(time.Second)

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Error in pruning expired key")
	}
}

func TestGoodLabel(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with the tag "red" and
	// verify that decryption with the tag "red" is allowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", "", &Usage{1, []string{"red"}, []string{"alice"}, time.Now().Add(duration), false})
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"red"}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestBadLabel(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with the tag "red" and
	// verify that decryption with the tag "blue" is disallowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", "", &Usage{1, []string{"red"}, nil, time.Now().Add(duration), true})
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"blue"}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Decryption of labeled key allowed without permission.")
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestGoodUser(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with tag and user
	// restrictions and verify that permissible decryption is allowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword", "",
		&Usage{
			1, []string{"red", "blue"},
			[]string{"ci", "buildeng", "user"},
			time.Now().Add(duration), false,
		},
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "ci", []string{"red"}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestBadUser(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with tag and user
	// restrictions and verify that illegal decryption is disallowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword", "",
		&Usage{
			1, []string{"red", "blue"},
			[]string{"ci", "buildeng", "user"},
			time.Now().Add(duration), false,
		},
	)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"blue"}, pubEncryptedKey)
	if err == nil {
		t.Fatalf("Decryption of labeled key allowed without permission.")
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}

func TestAnyUser(t *testing.T) {
	// Initialize passvault and keycache.  Delegate a key with tag and user
	// restrictions and verify that permissible decryption is allowed.
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	duration, _ := time.ParseDuration("1h")
	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword", "",
		&Usage{
			1, []string{"red", "blue"},
			nil,
			time.Now().Add(duration), true,
		},
	)

	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	dummy := make([]byte, 16)
	pubEncryptedKey, err := pr.EncryptKey(dummy)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = cache.DecryptKey(dummy, "user", "anybody", []string{"red"}, pubEncryptedKey)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 0 {
		t.Fatalf("Error in number of live keys %v", cache.UserKeys)
	}
}
