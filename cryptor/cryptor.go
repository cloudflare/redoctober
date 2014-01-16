// Package cryptor encrypts and decrypts files using the Red October
// vault and key cache.
//
// Copyright (c) 2013 CloudFlare, Inc.

package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"errors"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/padding"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/symcrypt"
	"sort"
	"strconv"
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
// by an RSA or EC key.
type SingleWrappedKey struct {
	Key    []byte
	aesKey []byte
}

// EncryptedData is the format for encrypted data containing all the
// keys necessary to decrypt it when delegated.
type EncryptedData struct {
	Version   int
	VaultId   int
	KeySet    []MultiWrappedKey
	KeySetRSA map[string]SingleWrappedKey
	IV        []byte
	Data      []byte
	Signature []byte
}

// encryptKey encrypts data with the key associated with name inner,
// then name outer
func encryptKey(nameInner, nameOuter string, clearKey []byte, pubKeys map[string]SingleWrappedKey) (out MultiWrappedKey, err error) {
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
	// For RSA and ECC records, use the public key from the passvault
	switch recInner.Type {
	case passvault.RSARecord, passvault.ECCRecord:
		if overrideInner, ok = pubKeys[nameInner]; !ok {
			err = errors.New("Missing user in file")
			return
		}

		if overrideOuter, ok = pubKeys[nameOuter]; !ok {
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

// unwrapKey decrypts first key in keys whose encryption keys are in keycache
func unwrapKey(keys []MultiWrappedKey, pubKeys map[string]SingleWrappedKey) (unwrappedKey []byte, err error) {
	var (
		keyFound  error
		fullMatch bool = false
	)

	for _, mwKey := range keys {
		if err != nil {
			return nil, err
		}

		tmpKeyValue := mwKey.Key

		for _, mwName := range mwKey.Name {
			pubEncrypted := pubKeys[mwName]
			// if this is null, it's an AES encrypted key
			if tmpKeyValue, keyFound = keycache.DecryptKey(tmpKeyValue, mwName, pubEncrypted.Key); keyFound != nil {
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

	if !fullMatch {
		err = errors.New("Need more delegated keys")
	}
	return
}

// mwkSorter describes a slice of MultiWrappedKeys to be sorted.
type mwkSorter struct {
	keySet []MultiWrappedKey
}

// Len is part of sort.Interface.
func (s *mwkSorter) Len() int {
	return len(s.keySet)
}

// Swap is part of sort.Interface.
func (s *mwkSorter) Swap(i, j int) {
	s.keySet[i], s.keySet[j] = s.keySet[j], s.keySet[i]
}

// Less is part of sort.Interface, it sorts lexicographically
// based on the list of names
func (s *mwkSorter) Less(i, j int) bool {
	var shorter = i
	if len(s.keySet[i].Name) > len(s.keySet[j].Name) {
		shorter = j
	}
	for index := range s.keySet[shorter].Name {
		if s.keySet[i].Name[index] != s.keySet[j].Name[index] {
			return s.keySet[i].Name[index] < s.keySet[j].Name[index]
		}
	}

	return false
}

// swkSorter joins a slice of names with SingleWrappedKeys to be sorted.
type pair struct {
	name string
	key  []byte
}

type swkSorter []pair

// Len is part of sort.Interface.
func (s swkSorter) Len() int {
	return len(s)
}

// Swap is part of sort.Interface.
func (s swkSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

// Less is part of sort.Interface.
func (s swkSorter) Less(i, j int) bool {
	return s[i].name < s[j].name
}

// computeHmac computes the signature of the encrypted data structure
// the signature takes into account every element of the EncryptedData
// structure, with all keys sorted alphabetically by name
func computeHmac(key []byte, encrypted EncryptedData) []byte {
	mac := hmac.New(sha1.New, key)

	// sort the multi-wrapped keys
	mwks := &mwkSorter{
		keySet: encrypted.KeySet,
	}
	sort.Sort(mwks)

	// sort the singly-wrapped keys
	var swks swkSorter
	for name, val := range encrypted.KeySetRSA {
		swks = append(swks, pair{name, val.Key})
	}
	sort.Sort(&swks)

	// start hashing
	mac.Write([]byte(strconv.Itoa(encrypted.Version)))
	mac.Write([]byte(strconv.Itoa(encrypted.VaultId)))

	// hash the multi-wrapped keys
	for _, mwk := range encrypted.KeySet {
		for _, name := range mwk.Name {
			mac.Write([]byte(name))
		}
		mac.Write(mwk.Key)
	}

	// hash the single-wrapped keys
	for index := range swks {
		mac.Write([]byte(swks[index].name))
		mac.Write(swks[index].key)
	}

	// hash the IV and data
	mac.Write(encrypted.IV)
	mac.Write(encrypted.Data)

	return mac.Sum(nil)
}

// Encrypt encrypts data with the keys associated with names. This
// requires a minimum of min keys to decrypt.  NOTE: as currently
// implemented, the maximum value for min is 2.
func Encrypt(in []byte, names []string, min int) (resp []byte, err error) {
	if min > 2 {
		return nil, errors.New("Minimum restricted to 2")
	}

	var encrypted EncryptedData
	encrypted.Version = DEFAULT_VERSION
	if encrypted.VaultId, err = passvault.GetVaultId(); err != nil {
		return
	}

	// Generate random IV and encryption key
	ivBytes, err := symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	// append used here to make a new slice from ivBytes and assign to
	// encrypted.IV

	encrypted.IV = append([]byte{}, ivBytes...)
	clearKey, err := symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	// Allocate set of keys to be able to cover all ordered subsets of
	// length 2 of names

	encrypted.KeySet = make([]MultiWrappedKey, len(names)*(len(names)-1))
	encrypted.KeySetRSA = make(map[string]SingleWrappedKey)

	var singleWrappedKey SingleWrappedKey
	for _, name := range names {
		rec, ok := passvault.GetRecord(name)
		if !ok {
			err = errors.New("Missing user on disk")
			return
		}

		if rec.GetType() == passvault.RSARecord || rec.GetType() == passvault.ECCRecord {
			// only wrap key with RSA key if found
			if singleWrappedKey.aesKey, err = symcrypt.MakeRandom(16); err != nil {
				return nil, err
			}

			if singleWrappedKey.Key, err = rec.EncryptKey(singleWrappedKey.aesKey); err != nil {
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

	clearFile := padding.AddPadding(in)

	encryptedFile := make([]byte, len(clearFile))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedFile, clearFile)

	encrypted.Data = encryptedFile

	hmacKey, err := passvault.GetHmacKey()
	if err != nil {
		return
	}
	encrypted.Signature = computeHmac(hmacKey, encrypted)

	return json.Marshal(encrypted)
}

// Decrypt decrypts a file using the keys in the key cache.
func Decrypt(in []byte) (resp []byte, err error) {
	// unwrap encrypted file
	var encrypted EncryptedData
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
			return
		}
	}

	// compute HMAC
	hmacKey, err := passvault.GetHmacKey()
	if err != nil {
		return
	}
	expectedMAC := computeHmac(hmacKey, encrypted)
	if !hmac.Equal(encrypted.Signature, expectedMAC) {
		err = errors.New("Signature mismatch")
		return
	}

	// decrypt file key with delegate keys
	var unwrappedKey = make([]byte, 16)
	if unwrappedKey, err = unwrapKey(encrypted.KeySet, encrypted.KeySetRSA); err != nil {
		return
	}

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
