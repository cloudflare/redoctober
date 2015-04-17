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
	"sort"
	"strconv"

	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/padding"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/symcrypt"
)

const (
	DEFAULT_VERSION = 1
)

type Cryptor struct {
	records *passvault.Records
	cache   *keycache.Cache
}

func New(records *passvault.Records, cache *keycache.Cache) Cryptor {
	return Cryptor{records, cache}
}

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
	Labels    []string
	KeySet    []MultiWrappedKey
	KeySetRSA map[string]SingleWrappedKey
	IV        []byte
	Data      []byte
	Signature []byte
}

type pair struct {
	name string
	key  []byte
}

type mwkSlice []MultiWrappedKey
type swkSlice []pair

func (s mwkSlice) Len() int             { return len(s) }
func (s mwkSlice) Swap(i, j int)        { s[i], s[j] = s[j], s[i] }
func (s mwkSlice) Less(i, j int) bool { // Alphabetic order
	var shorter = i
	if len(s[i].Name) > len(s[j].Name) {
		shorter = j
	}

	for index := range s[shorter].Name {
		if s[i].Name[index] != s[j].Name[index] {
			return s[i].Name[index] < s[j].Name[index]
		}
	}

	return false
}

func (s swkSlice) Len() int           { return len(s) }
func (s swkSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s swkSlice) Less(i, j int) bool { return s[i].name < s[j].name }

// computeHmac computes the signature of the encrypted data structure
// the signature takes into account every element of the EncryptedData
// structure, with all keys sorted alphabetically by name
func (encrypted *EncryptedData) computeHmac(key []byte) []byte {
	mac := hmac.New(sha1.New, key)

	// sort the multi-wrapped keys
	mwks := mwkSlice(encrypted.KeySet)
	sort.Sort(mwks)

	// sort the singly-wrapped keys
	var swks swkSlice
	for name, val := range encrypted.KeySetRSA {
		swks = append(swks, pair{name, val.Key})
	}
	sort.Sort(&swks)

	// sort the labels
	sort.Strings(encrypted.Labels)

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

	// hash the labels
	for index := range encrypted.Labels {
		mac.Write([]byte(encrypted.Labels[index]))
	}

	return mac.Sum(nil)
}

// wrapKey encrypts the clear key such that a minimum number of delegated keys
// are required to decrypt.  NOTE:  Currently the max value for min is 2.
func (encrypted *EncryptedData) wrapKey(records *passvault.Records, clearKey []byte, names []string, min int) (err error) {
	// Generate a random AES key for each user and RSA/ECIES encrypt it
	encrypted.KeySetRSA = make(map[string]SingleWrappedKey, len(names))

	for _, name := range names {
		rec, ok := records.GetRecord(name)
		if !ok {
			err = errors.New("Missing user on disk")
			return
		}

		var singleWrappedKey SingleWrappedKey

		if singleWrappedKey.aesKey, err = symcrypt.MakeRandom(16); err != nil {
			return err
		}

		if singleWrappedKey.Key, err = rec.EncryptKey(singleWrappedKey.aesKey); err != nil {
			return err
		}

		encrypted.KeySetRSA[name] = singleWrappedKey
	}

	// encrypt file key with every combination of two keys
	encrypted.KeySet = make([]MultiWrappedKey, 0)

	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			var outerCrypt, innerCrypt cipher.Block
			keyBytes := make([]byte, 16)

			outerCrypt, err = aes.NewCipher(encrypted.KeySetRSA[names[i]].aesKey)
			if err != nil {
				return
			}

			innerCrypt, err = aes.NewCipher(encrypted.KeySetRSA[names[j]].aesKey)
			if err != nil {
				return
			}

			innerCrypt.Encrypt(keyBytes, clearKey)
			outerCrypt.Encrypt(keyBytes, keyBytes)

			out := MultiWrappedKey{
				Name: []string{names[i], names[j]},
				Key:  keyBytes,
			}

			encrypted.KeySet = append(encrypted.KeySet, out)
		}
	}

	return nil
}

// unwrapKey decrypts first key in keys whose encryption keys are in keycache
func (encrypted *EncryptedData) unwrapKey(cache *keycache.Cache, user string) (unwrappedKey []byte, names []string, err error) {
	var (
		keyFound  error
		fullMatch bool = false
		nameSet        = map[string]bool{}
	)

	for _, mwKey := range encrypted.KeySet {
		// validate the size of the keys
		if len(mwKey.Key) != 16 {
			err = errors.New("Invalid Input")
		}

		if err != nil {
			return nil, nil, err
		}

		tmpKeyValue := mwKey.Key

		for _, mwName := range mwKey.Name {
			pubEncrypted := encrypted.KeySetRSA[mwName]
			// if this is null, it's an AES encrypted key
			if tmpKeyValue, keyFound = cache.DecryptKey(tmpKeyValue, mwName, user, encrypted.Labels, pubEncrypted.Key); keyFound != nil {
				break
			}
			nameSet[mwName] = true
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
		names = nil
	}

	names = make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	return
}

// Encrypt encrypts data with the keys associated with names. This
// requires a minimum of min keys to decrypt.  NOTE: as currently
// implemented, the maximum value for min is 2.
func (c *Cryptor) Encrypt(in []byte, labels, names []string, min int) (resp []byte, err error) {
	if min > 2 {
		return nil, errors.New("Minimum restricted to 2")
	}

	var encrypted EncryptedData
	encrypted.Version = DEFAULT_VERSION
	if encrypted.VaultId, err = c.records.GetVaultId(); err != nil {
		return
	}

	// Generate random IV and encryption key
	encrypted.IV, err = symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	clearKey, err := symcrypt.MakeRandom(16)
	if err != nil {
		return
	}

	err = encrypted.wrapKey(c.records, clearKey, names, min)
	if err != nil {
		return
	}

	// encrypt file with clear key
	aesCrypt, err := aes.NewCipher(clearKey)
	if err != nil {
		return
	}

	clearFile := padding.AddPadding(in)

	encryptedFile := make([]byte, len(clearFile))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, encrypted.IV)
	aesCBC.CryptBlocks(encryptedFile, clearFile)

	encrypted.Data = encryptedFile
	encrypted.Labels = labels

	hmacKey, err := c.records.GetHmacKey()
	if err != nil {
		return
	}
	encrypted.Signature = encrypted.computeHmac(hmacKey)

	return json.Marshal(encrypted)
}

// Decrypt decrypts a file using the keys in the key cache.
func (c *Cryptor) Decrypt(in []byte, user string) (resp []byte, names []string, err error) {
	// unwrap encrypted file
	var encrypted EncryptedData
	if err = json.Unmarshal(in, &encrypted); err != nil {
		return
	}
	if encrypted.Version != DEFAULT_VERSION {
		return nil, nil, errors.New("Unknown version")
	}

	// make sure file was encrypted with the active vault
	vaultId, err := c.records.GetVaultId()
	if err != nil {
		return
	}
	if encrypted.VaultId != vaultId {
		return nil, nil, errors.New("Wrong vault")
	}

	// compute HMAC
	hmacKey, err := c.records.GetHmacKey()
	if err != nil {
		return
	}
	expectedMAC := encrypted.computeHmac(hmacKey)
	if !hmac.Equal(encrypted.Signature, expectedMAC) {
		err = errors.New("Signature mismatch")
		return
	}

	// decrypt file key with delegate keys
	var unwrappedKey = make([]byte, 16)
	unwrappedKey, names, err = encrypted.unwrapKey(c.cache, user)
	if err != nil {
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

	resp, err = padding.RemovePadding(clearData)
	return
}
