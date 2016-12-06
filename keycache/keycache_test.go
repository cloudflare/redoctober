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

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 2, "", "1h")
	if err != nil {
		t.Fatalf("%v", err)
	}

	removed := cache.Refresh()
	if removed != 0 {
		t.Fatalf("No active users should have been removed")
	}

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
		t.Fatal("cache.DecryptKey didnt decrypt the right key!")
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

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, nil, 10, "", "10s")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache.Refresh()
	if len(cache.UserKeys) != 1 {
		t.Fatalf("Error in number of live keys")
	}

	time.Sleep(11 * time.Second)

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

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, []string{"red"}, 1, "", "1h")
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

	err = cache.AddKeyFromRecord(pr, "user", "weakpassword", nil, []string{"red"}, 1, "", "1h")
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

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "1h",
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

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "1h",
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

func TestRefresh(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	pr, err := records.AddNewRecord("user", "weakpassword", true, passvault.DefaultRecordType)
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	err = cache.AddKeyFromRecord(
		pr, "user", "weakpassword",
		[]string{"ci", "buildeng", "user"},
		[]string{"red", "blue"},
		1, "", "10s",
	)
	if err != nil {
		t.Fatalf("%v", err)
	}

	removed := cache.Refresh()
	if removed != 0 {
		t.Fatalf("Refresh should not have removed any active users.")
	}

	time.Sleep(10 * time.Second)

	removed = cache.Refresh()
	if removed != 1 {
		t.Fatalf("Refresh should have removed an active user, removed %d", removed)
	}

	if len(cache.GetSummary()) != 0 {
		t.Fatalf("There should be no active users in the cache, but there are %d", len(cache.GetSummary()))
	}
}

func cmpEntry(c, d ActiveUser) bool {
	if c.Uses != d.Uses {
		return false
	}

	if len(c.Labels) != len(d.Labels) {
		return false
	}

	for i := range c.Labels {
		if c.Labels[i] != d.Labels[i] {
			return false
		}
	}

	if len(c.Users) != len(d.Users) {
		return false
	}

	for i := range c.Users {
		if c.Users[i] != d.Users[i] {
			return false
		}
	}

	if c.Expiry != d.Expiry {
		return false
	}

	return true
}

func cmpCache(a, b Cache) bool {
	if len(a.UserKeys) != len(b.UserKeys) {
		return false
	}

	for aIndex, aUser := range a.UserKeys {
		bUser, ok := b.UserKeys[aIndex]
		if !ok {
			return false
		}

		if !cmpEntry(aUser, bUser) {
			return false
		}
	}

	return true
}

func TestNewFrom(t *testing.T) {
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cache := NewCache()

	users := []string{"alice", "bob", "carol"}
	for _, user := range users {
		pr, err := records.AddNewRecord(user, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		err = cache.AddKeyFromRecord(
			pr, user, "weakpassword",
			[]string{"ci", "buildeng", "user"},
			[]string{"red", "blue"},
			1, "", "1h")
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	pr, ok := records.GetRecord("alice")
	if !ok {
		t.Fatal("Couldn't retrieve 'alice' record.")
	}

	err = cache.AddKeyFromRecord(pr, "alice", "weakpassword",
		[]string{"ci", "alice"}, []string{"blue", "yellow"},
		2, "slotname", "1h")
	if err != nil {
		t.Fatal(err)
	}

	summary := cache.GetSummary()
	cache2 := NewFrom(summary)
	if !cmpCache(cache, *cache2) {
		t.Fatal("caches don't match")
	}

}
