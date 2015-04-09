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

// UserKeys is the set of decrypted keys in memory, indexed by name.
var UserKeys map[string]ActiveUser = make(map[string]ActiveUser)

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

	aesKey []byte
	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

// matchUser returns the matching active user if present
// and a boolean to indicate its presence.
func matchUser(name, user string, labels []string) (out ActiveUser, present bool) {
	key, present := UserKeys[name]
	if present {
		if key.Usage.matches(user, labels) {
			return key, true
		} else {
			present = false
		}
	}

	return
}

// setUser takes an ActiveUser and adds it to the cache.
func setUser(in ActiveUser, name string) {
	UserKeys[name] = in
}

// matchesLabel returns true if this usage applies the user and label
// an empty array of Users indicates that all users are valid
func (usage Usage) matchesLabel(labels []string) bool {
	// if asset has no labels always match
	if len(labels) == 0 {
		return true
	}
	//
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

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func useKey(name, user string, labels []string) {
	if val, present := matchUser(name, user, labels); present {
		val.Usage.Uses -= 1
		setUser(val, name)
	}
}

// GetSummary returns the list of active user keys.
func GetSummary() map[string]ActiveUser {
	return UserKeys
}

// FlushCache removes all delegated keys.
func FlushCache() {
	for name := range UserKeys {
		delete(UserKeys, name)
	}
}

// Refresh purges all expired or used up keys.
func Refresh() {
	for name, active := range UserKeys {
		if active.Usage.Expiry.Before(time.Now()) || active.Usage.Uses <= 0 {
			log.Println("Record expired", name, active.Usage.Users, active.Usage.Labels, active.Usage.Expiry)
			delete(UserKeys, name)
		}
	}
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func AddKeyFromRecord(record passvault.PasswordRecord, name, password string, users, labels []string, uses int, durationString string) (err error) {
	var current ActiveUser

	Refresh()

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
	case passvault.AESRecord:
		current.aesKey, err = record.GetKeyAES(password)
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
	setUser(current, name)

	return
}

// EncryptKey encrypts a 16 byte key using the cached key corresponding to name.
// For AES keys, use the cached key.
// For RSA and EC keys, the cache is not necessary; use the override
// key instead.
func EncryptKey(in []byte, name string, override []byte) (out []byte, err error) {
	Refresh()

	aesKey := override

	// if the override key is not set, extract from the cache
	if aesKey == nil {
		encryptKey, ok := matchUser(name, name, []string{})
		if !ok {
			return nil, errors.New("Key not delegated")
		}

		switch encryptKey.Type {
		case passvault.AESRecord:
			aesKey = encryptKey.aesKey

		default:
			return out, errors.New("Require override for key")
		}

		useKey(name, name, []string{})
	}

	// encrypt
	aesSession, err := aes.NewCipher(aesKey)
	if err != nil {
		return
	}
	out = make([]byte, 16)
	aesSession.Encrypt(out, in)

	return
}

// DecryptKey decrypts a 16 byte key using the key corresponding to the name parameter
// for AES keys, the cached AES key is used directly to decrypt in
// for RSA and EC keys, the cached RSA/EC key is used to decrypt
// the pubEncryptedKey which is then used to decrypt the input
// buffer.
func DecryptKey(in []byte, name, user string, labels []string, pubEncryptedKey []byte) (out []byte, err error) {
	Refresh()

	decryptKey, ok := matchUser(name, user, labels)
	if !ok {
		return nil, errors.New("Key not delegated")
	}

	var aesKey []byte

	// pick the aesKey to use for decryption
	switch decryptKey.Type {
	case passvault.AESRecord:
		aesKey = decryptKey.aesKey

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

	useKey(name, user, labels)

	return
}
