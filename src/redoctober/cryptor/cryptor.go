// Package cryptor encrypts and decrypts files using the Red October
// vault and key cache.
//
// Copyright (c) 2013 CloudFlare, Inc.

package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"redoctober/keycache"
	"redoctober/padding"
	"redoctober/passvault"
)

const (
	DEFAULT_VERSION = 1
)

// MultiWrappedKey is a structure containing a 16-byte key encrypted
// once for each of the keys corresponding to the names of the users
// in Name in order.
type MultiWrappedKey struct {
	Name []string
	Key  []byte
}

// SingleWrappedKey is a structure containing a 16-byte key encrypted
// by an RSA key.
type SingleWrappedKey struct {
	Key    []byte
	aesKey []byte
}

// EncryptedFile is the format for encrypted data containing all the
// keys necessary to decrypt it when delegated.
type EncryptedFile struct {
	Version   int
	VaultId   int
	KeySet    []MultiWrappedKey
	KeySetRSA map[string]SingleWrappedKey
	IV        []byte
	Data      []byte
	Signature []byte
}

// Private Functions
// Helper to make new buffer full of random data
func makeRandom(length int) (bytes []byte, err error) {
	bytes = make([]byte, 16)
	n, err := rand.Read(bytes)
	if n != len(bytes) || err != nil {
		return
	}
	return
}

// encrypt clearKey with the key associated with name inner, then name
// outer
func encryptKey(nameInner, nameOuter string, clearKey []byte, rsaKeys map[string]SingleWrappedKey) (out MultiWrappedKey, err error) {
	out.Name = []string{nameOuter, nameInner}

	recInner, ok := passvault.GetRecord(nameInner)
	if !ok {
		err = errors.New("Missing user on disk")
		return
	}

	recOuter, ok := passvault.GetRecord(nameOuter)
	if !ok {
		err = errors.New("Missing user on disk")
		return
	}

	if recInner.Type != recOuter.Type {
		err = errors.New("Mismatched record types")
		return
	}

	var keyBytes []byte
	var overrideInner SingleWrappedKey
	var overrideOuter SingleWrappedKey

	// For AES records, use the live user key
	// For RSA records, use the public key from the passvault
	switch recInner.Type {
	case passvault.RSARecord:
		overrideInner, ok = rsaKeys[nameInner]
		if !ok {
			err = errors.New("Missing user in file")
			return
		}

		overrideOuter, ok = rsaKeys[nameOuter]
		if !ok {
			err = errors.New("Missing user in file")
			return
		}

	case passvault.AESRecord:
		break

	default:
		return out, errors.New("Unknown record type inner")
	}

	// double-wrap the keys
	if keyBytes, err = keycache.EncryptKey(clearKey, nameInner, overrideInner.aesKey); err != nil {
		return out, err
	}
	if keyBytes, err = keycache.EncryptKey(keyBytes, nameOuter, overrideOuter.aesKey); err != nil {
		return out, err
	}

	out.Key = keyBytes

	return
}

// decrypt first key in keys whose encryption keys are in keycache
func unwrapKey(keys []MultiWrappedKey, rsaKeys map[string]SingleWrappedKey) (unwrappedKey []byte, err error) {
	var (
		keyFound  error
		fullMatch bool = false
	)
	for _, mwKey := range keys {
		tmpKeyValue := mwKey.Key
		if err != nil {
			return nil, err
		}

		for _, mwName := range mwKey.Name {
			rsaEncrypted := rsaKeys[mwName]
			// if this is null, it's an AES encrypted key
			tmpKeyValue, keyFound = keycache.DecryptKey(tmpKeyValue, mwName, rsaEncrypted.Key)
			if keyFound != nil {
				break
			}
		}
		if keyFound == nil {
			fullMatch = true
			// concatenate all the decrypted bytes
			unwrappedKey = tmpKeyValue
			break
		}
	}

	if fullMatch == false {
		err = errors.New("Need more delegated keys")
	}
	return
}

// Encrypt encrypts data with the keys associated with names
// This requires a minimum of min keys to decrypt.
// NOTE: as currently implemented, the maximum value for min is 2.
func Encrypt(in []byte, names []string, min int) (resp []byte, err error) {
	if min > 2 {
		return nil, errors.New("Minimum restricted to 2")
	}

	// decode data to encrypt
	clearFile := padding.AddPadding(in)

	// set up encrypted data structure
	var encrypted EncryptedFile
	encrypted.Version = DEFAULT_VERSION
	if encrypted.VaultId, err = passvault.GetVaultId(); err != nil {
		return
	}

	// generate random IV and encryption key
	ivBytes, err := makeRandom(16)
	if err != nil {
		return
	}
	encrypted.IV = append([]byte{}, ivBytes...)
	clearKey, err := makeRandom(16)
	if err != nil {
		return
	}

	// allocate set of keys to be able to cover all ordered subsets
	// of length 2 of names
	encrypted.KeySet = make([]MultiWrappedKey, len(names)*(len(names)-1))

	// create map to hold RSA encrypted keys
	encrypted.KeySetRSA = make(map[string]SingleWrappedKey)

	var singleWrappedKey SingleWrappedKey
	for _, name := range names {
		rec, ok := passvault.GetRecord(name)
		if !ok {
			err = errors.New("Missing user on disk")
			return
		}

		if rec.GetType() == passvault.RSARecord {
			// only wrap key with RSA key if found
			singleWrappedKey.aesKey, err = makeRandom(16)
			if err != nil {
				return nil, err
			}

			singleWrappedKey.Key, err = rec.EncryptKey(singleWrappedKey.aesKey)
			if err != nil {
				return nil, err
			}
			encrypted.KeySetRSA[name] = singleWrappedKey
		} else {
			err = nil
		}
	}

	// encrypt file key with every combination of two keys
	var n int
	for _, nameOuter := range names {
		for _, nameInner := range names {
			if nameInner != nameOuter {
				encrypted.KeySet[n], err = encryptKey(nameInner, nameOuter, clearKey, encrypted.KeySetRSA)
				n += 1
			}
			if err != nil {
				return
			}
		}
	}

	// encrypt file with clear key
	aesCrypt, err := aes.NewCipher(clearKey)
	if err != nil {
		return
	}
	encryptedFile := make([]byte, len(clearFile))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedFile, clearFile)

	// encode result
	encrypted.Data = encryptedFile

	// compute HMAC
	hmacKey, err := passvault.GetHmacKey()
	if err != nil {
		return
	}
	mac := hmac.New(sha1.New, hmacKey)
	mac.Write(encrypted.Data)
	encrypted.Signature = mac.Sum(nil)

	return json.Marshal(encrypted)
}

// Decrypt decrypts a file using the keys in the key cache.
func Decrypt(in []byte) (resp []byte, err error) {
	// unwrap encrypted file
	var encrypted EncryptedFile
	if err = json.Unmarshal(in, &encrypted); err != nil {
		return
	}
	if encrypted.Version != DEFAULT_VERSION {
		return nil, errors.New("Unknown version")
	}

	// make sure file was encrypted with the active vault
	vaultId, err := passvault.GetVaultId()
	if err != nil {
		return
	}
	if encrypted.VaultId != vaultId {
		return nil, errors.New("Wrong vault")
	}

	// validate the size of the keys
	for _, multiKey := range encrypted.KeySet {
		if len(multiKey.Key) != 16 {
			err = errors.New("Invalid Input")
		}
	}

	// compute HMAC
	hmacKey, err := passvault.GetHmacKey()
	if err != nil {
		return
	}
	mac := hmac.New(sha1.New, hmacKey)
	mac.Write(encrypted.Data)
	expectedMAC := mac.Sum(nil)
	if !hmac.Equal(encrypted.Signature, expectedMAC) {
		err = errors.New("Signature mismatch")
		return
	}

	// decrypt file key with delegate keys
	var unwrappedKey = make([]byte, 16)
	if unwrappedKey, err = unwrapKey(encrypted.KeySet, encrypted.KeySetRSA); err != nil {
		return
	}

	// set up the decryption context
	aesCrypt, err := aes.NewCipher(unwrappedKey)
	if err != nil {
		return
	}
	clearData := make([]byte, len(encrypted.Data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, encrypted.IV)

	// decrypt contents of file
	aesCBC.CryptBlocks(clearData, encrypted.Data)

	return padding.RemovePadding(clearData)
}
