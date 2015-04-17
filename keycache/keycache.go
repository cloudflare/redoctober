// Package keycache provides the ability to hold active keys in memory
// for the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package keycache

import (
	"crypto/aes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"errors"
	"log"
	"time"

	"github.com/cloudflare/redoctober/ecdh"
	"github.com/cloudflare/redoctober/passvault"
)

// Usage holds the permissions of a delegated permission
type Usage struct {
	Uses   int       // Number of uses delegated
	Labels []string  // File labels allowed to decrypt
	Users  []string  // Set of users allows to decrypt
	Expiry time.Time // Expiration of usage
}

// ActiveUser holds the information about an actively delegated key.
type ActiveUser struct {
	Usage
	Admin bool
	Type  string

	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

type Cache struct {
	UserKeys map[string]ActiveUser // Decrypted keys in memory, indexed by name.
}

// matchesLabel returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matchesLabel(labels []string) bool {
	// if asset has no labels always match
	if len(labels) == 0 {
		return true
	}

	for _, validLabel := range usage.Labels {
		for _, label := range labels {
			if label == validLabel {
				return true
			}
		}
	}
	return false
}

// matches returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matches(user string, labels []string) bool {
	if !usage.matchesLabel(labels) {
		return false
	}
	// if usage lists no users, always match
	if len(usage.Users) == 0 {
		return true
	}
	for _, validUser := range usage.Users {
		if user == validUser {
			return true
		}
	}
	return false
}

func NewCache() Cache {
	return Cache{make(map[string]ActiveUser)}
}

// setUser takes an ActiveUser and adds it to the cache.
func (cache *Cache) setUser(in ActiveUser, name string) {
	cache.UserKeys[name] = in
}

// matchUser returns the matching active user if present
// and a boolean to indicate its presence.
func (cache *Cache) matchUser(name, user string, labels []string) (out ActiveUser, present bool) {
	key, present := cache.UserKeys[name]
	if present {
		if key.Usage.matches(user, labels) {
			return key, true
		} else {
			present = false
		}
	}

	return
}

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func (cache *Cache) useKey(name, user string, labels []string) {
	if val, present := cache.matchUser(name, user, labels); present {
		val.Usage.Uses -= 1
		cache.setUser(val, name)
	}
}

// GetSummary returns the list of active user keys.
func (cache *Cache) GetSummary() map[string]ActiveUser {
	return cache.UserKeys
}

// FlushCache removes all delegated keys.
func (cache *Cache) FlushCache() {
	for name := range cache.UserKeys {
		delete(cache.UserKeys, name)
	}
}

// Refresh purges all expired or used up keys.
func (cache *Cache) Refresh() {
	for name, active := range cache.UserKeys {
		if active.Usage.Expiry.Before(time.Now()) || active.Usage.Uses <= 0 {
			log.Println("Record expired", name, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			delete(cache.UserKeys, name)
		}
	}
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func (cache *Cache) AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, durationString string) (err error) {
	var current ActiveUser

	cache.Refresh()

	// compute exipiration
	duration, err := time.ParseDuration(durationString)
	if err != nil {
		return
	}
	current.Usage.Uses = uses
	current.Usage.Expiry = time.Now().Add(duration)
	current.Usage.Users = users
	current.Usage.Labels = labels

	// get decryption keys
	switch record.Type {
	case passvault.RSARecord:
		current.rsaKey, err = record.GetKeyRSA(password)
	case passvault.ECCRecord:
		current.eccKey, err = record.GetKeyECC(password)
	default:
		err = errors.New("Unknown record type")
	}

	if err != nil {
		return
	}

	// set types
	current.Type = record.Type
	current.Admin = record.Admin

	// add current to map (overwriting previous for this name)
	cache.setUser(current, name)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// For RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func (cache *Cache) DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	cache.Refresh()

	decryptKey, ok := cache.matchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.RSARecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = rsa.DecryptOAEP(sha1.New(), rand.Reader, &decryptKey.rsaKey, pubEncryptedKey, nil)
		if err != nil {
			return out, err
		}
	case passvault.ECCRecord:
		// extract the aes key from the pubEncryptedKey
		aesKey, err = ecdh.Decrypt(decryptKey.eccKey, pubEncryptedKey)

		if err != nil {
			return out, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	// decrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return out, err
	}
	out = make([]byte, 16)
	aesSession.Decrypt(out, in)

	cache.useKey(name, user, labels)

	return
}
