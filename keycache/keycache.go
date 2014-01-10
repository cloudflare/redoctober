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
	"github.com/cloudflare/redoctober/ecdh"
	"github.com/cloudflare/redoctober/passvault"
	"log"
	"time"
)

// UserKeys is the set of decrypted keys in memory, indexed by name.
var UserKeys map[string]ActiveUser = make(map[string]ActiveUser)

// ActiveUser holds the information about an actively delegated key.
type ActiveUser struct {
	Admin  bool
	Type   string
	Expiry time.Time
	Uses   int

	aesKey []byte
	rsaKey rsa.PrivateKey
	eccKey *ecdsa.PrivateKey
}

// matchUser returns the matching active user if present
// and a boolean to indicate its presence.
func matchUser(name string) (out ActiveUser, present bool) {
	out, present = UserKeys[name]
	return
}

// setUser takes an ActiveUser and adds it to the cache.
func setUser(in ActiveUser, name string) {
	UserKeys[name] = in
}

// useKey decrements the counter on an active key
// for decryption or symmetric encryption
func useKey(name string) {
	if val, present := matchUser(name); present {
		val.Uses -= 1
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
		if active.Expiry.Before(time.Now()) || active.Uses <= 0 {
			log.Println("Record expired", name, active.Expiry)
			delete(UserKeys, name)
		}
	}
}

// AddKeyFromRecord decrypts a key for a given record and adds it to the cache.
func AddKeyFromRecord(record passvault.PasswordRecord, name string, password string, uses int, durationString string) (err error) {
	var current ActiveUser

	Refresh()

	// compute exipiration
	duration, err := time.ParseDuration(durationString)
	if err != nil {
		return
	}
	current.Uses = uses
	current.Expiry = time.Now().Add(duration)

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
		encryptKey, ok := matchUser(name)
		if !ok {
			return nil, errors.New("Key not delegated")
		}

		switch encryptKey.Type {
		case passvault.AESRecord:
			aesKey = encryptKey.aesKey

		default:
			return out, errors.New("Require override for key")
		}

		useKey(name)
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
func DecryptKey(in []byte, name string, pubEncryptedKey []byte) (out []byte, err error) {
	Refresh()

	decryptKey, ok := matchUser(name)
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

	useKey(name)

	return
}
