// Package passvault manages the vault containing user records on
// disk. It contains usernames and associated passwords which are
// stored hashed (with salt) using scrypt.
//
// Copyright (c) 2013 CloudFlare, Inc.

package passvault

import (
	"bytes"
	"code.google.com/p/go.crypto/scrypt"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"github.com/cloudflare/redoctober/padding"
	"io/ioutil"
	"math/big"
	mrand "math/rand"
	"os"
)

// Constants for record type
const (
	AESRecord = "AES"
	RSARecord = "RSA"
	ECCRecord = "ECC"
)

// Constants for scrypt
const (
	KEYLENGTH = 16    // 16-byte output from scrypt
	N         = 16384 // Cost parameter
	R         = 8     // Block size
	P         = 1     // Parallelization factor

	DEFAULT_VERSION = 1
)

// Path of current vault
var localPath string

// PasswordRecord is the structure used to store password and key
// material for a single user name. It is written and read from
// storage in JSON format.
type PasswordRecord struct {
	Type           string
	PasswordSalt   []byte
	HashedPassword []byte
	KeySalt        []byte
	AESKey         []byte
	RSAKey         struct {
		RSAExp      []byte
		RSAExpIV    []byte
		RSAPrimeP   []byte
		RSAPrimePIV []byte
		RSAPrimeQ   []byte
		RSAPrimeQIV []byte
		RSAPublic   rsa.PublicKey
	}
	Admin bool
}

// diskRecords is the structure used to read and write a JSON file
// containing the contents of a password vault
type diskRecords struct {
	Version   int
	VaultId   int
	HmacKey   []byte
	Passwords map[string]PasswordRecord
}

// records is the set of encrypted records read from disk and
// unmarshalled
var records diskRecords

// Summary is a minmial account summary.
type Summary struct {
	Admin bool
	Type  string
}

func init() {
	// seed math.random from crypto.random
	seedBytes, _ := makeRandom(8)
	seedBuf := bytes.NewBuffer(seedBytes)
	n64, _ := binary.ReadVarint(seedBuf)
	mrand.Seed(n64)
}

// hashPassword takes a password and derives a scrypt salted and hashed
// version
func hashPassword(password string, salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), salt, N, R, P, KEYLENGTH)
}

// makeRandom is a helper that makes a new buffer full of random data
func makeRandom(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// encryptRSARecord takes an RSA private key and encrypts it with
// a password key
func encryptRSARecord(newRec *PasswordRecord, rsaPriv *rsa.PrivateKey, passKey []byte) (err error) {
	if newRec.RSAKey.RSAExpIV, err = makeRandom(16); err != nil {
		return
	}

	paddedExponent := padding.AddPadding(rsaPriv.D.Bytes())
	if newRec.RSAKey.RSAExp, err = encryptCBC(paddedExponent, newRec.RSAKey.RSAExpIV, passKey); err != nil {
		return
	}

	if newRec.RSAKey.RSAPrimePIV, err = makeRandom(16); err != nil {
		return
	}

	paddedPrimeP := padding.AddPadding(rsaPriv.Primes[0].Bytes())
	if newRec.RSAKey.RSAPrimeP, err = encryptCBC(paddedPrimeP, newRec.RSAKey.RSAPrimePIV, passKey); err != nil {
		return
	}

	if newRec.RSAKey.RSAPrimeQIV, err = makeRandom(16); err != nil {
		return
	}

	paddedPrimeQ := padding.AddPadding(rsaPriv.Primes[1].Bytes())
	newRec.RSAKey.RSAPrimeQ, err = encryptCBC(paddedPrimeQ, newRec.RSAKey.RSAPrimeQIV, passKey)
	return
}

// createPasswordRec creates a new record from a username and password
func createPasswordRec(password string, admin bool) (newRec PasswordRecord, err error) {
	newRec.Type = RSARecord

	if newRec.PasswordSalt, err = makeRandom(16); err != nil {
		return
	}

	if newRec.HashedPassword, err = hashPassword(password, newRec.PasswordSalt); err != nil {
		return
	}

	if newRec.KeySalt, err = makeRandom(16); err != nil {
		return
	}

	passKey, err := derivePasswordKey(password, newRec.KeySalt)
	if err != nil {
		return
	}

	// generate a key pair
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}

	// encrypt RSA key with password key
	if err = encryptRSARecord(&newRec, rsaPriv, passKey); err != nil {
		return
	}

	newRec.RSAKey.RSAPublic = rsaPriv.PublicKey

	// encrypt AES key with password key
	aesKey, err := makeRandom(16)
	if err != nil {
		return
	}

	if newRec.AESKey, err = encryptECB(aesKey, passKey); err != nil {
		return
	}

	newRec.Admin = admin

	return
}

// derivePasswordKey generates a key from a password (and salt) using
// scrypt
func derivePasswordKey(password string, keySalt []byte) ([]byte, error) {
	return scrypt.Key([]byte(password), keySalt, N, R, P, KEYLENGTH)
}

// decryptECB decrypts bytes using a key in AES ECB mode.
func decryptECB(data, key []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	decryptedData = make([]byte, len(data))
	aesCrypt.Decrypt(decryptedData, data)

	return
}

// encryptECB encrypts bytes using a key in AES ECB mode.
func encryptECB(data, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}

	encryptedData = make([]byte, len(data))
	aesCrypt.Encrypt(encryptedData, data)

	return
}

// decryptCBC decrypt bytes using a key and IV with AES in CBC mode.
func decryptCBC(data, iv, key []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	decryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(decryptedData, data)

	return
}

// encryptCBC encrypt data using a key and IV with AES in CBC mode.
func encryptCBC(data, iv, key []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	encryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCEncrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(encryptedData, data)

	return
}

// InitFromDisk reads the record from disk and initialize global context.
func InitFromDisk(path string) error {
	jsonDiskRecord, err := ioutil.ReadFile(path)

	// It's OK for the file to be missing, we'll create it later if
	// anything is added.

	if err != nil && !os.IsNotExist(err) {
		return err
	}

	// Initialized so that we can determine later if anything was read
	// from the file.

	records.Version = 0

	if len(jsonDiskRecord) != 0 {
		if err = json.Unmarshal(jsonDiskRecord, &records); err != nil {
			return err
		}
	}

	formatErr := errors.New("Format error")
	for _, rec := range records.Passwords {
		if len(rec.PasswordSalt) != 16 {
			return formatErr
		}
		if len(rec.HashedPassword) != 16 {
			return formatErr
		}
		if len(rec.KeySalt) != 16 {
			return formatErr
		}
		if rec.Type == AESRecord {
			if len(rec.AESKey) != 16 {
				return formatErr
			}
		}
		if rec.Type == RSARecord {
			if len(rec.RSAKey.RSAExp) == 0 || len(rec.RSAKey.RSAExp)%16 != 0 {
				return formatErr
			}
			if len(rec.RSAKey.RSAPrimeP) == 0 || len(rec.RSAKey.RSAPrimeP)%16 != 0 {
				return formatErr
			}
			if len(rec.RSAKey.RSAPrimeQ) == 0 || len(rec.RSAKey.RSAPrimeQ)%16 != 0 {
				return formatErr
			}
			if len(rec.RSAKey.RSAExpIV) != 16 {
				return formatErr
			}
			if len(rec.RSAKey.RSAPrimePIV) != 16 {
				return formatErr
			}
			if len(rec.RSAKey.RSAPrimeQIV) != 16 {
				return formatErr
			}
		}
	}

	// If the Version field is 0 then it indicates that nothing was
	// read from the file and so it needs to be initialized.

	if records.Version == 0 {
		records.Version = DEFAULT_VERSION
		records.VaultId = mrand.Int()
		records.HmacKey, err = makeRandom(16)
		if err != nil {
			return err
		}
		records.Passwords = make(map[string]PasswordRecord)
	}

	localPath = path

	return nil
}

// WriteRecordsToDisk saves the current state of the records to disk.
func WriteRecordsToDisk() error {
	if !IsInitialized() {
		return errors.New("Path not initialized")
	}

	if jsonDiskRecord, err := json.Marshal(records); err == nil {
		return ioutil.WriteFile(localPath, jsonDiskRecord, 0644)
	} else {
		return err
	}
}

// AddNewRecord adds a new record for a given username and password.
func AddNewRecord(name, password string, admin bool) (PasswordRecord, error) {
	if pr, err := createPasswordRec(password, admin); err == nil {
		SetRecord(pr, name)
		return pr, WriteRecordsToDisk()
	} else {
		return pr, err
	}
}

// ChangePassword changes the password for a given user.
func ChangePassword(name, password, newPassword string) (err error) {
	pr, ok := GetRecord(name)
	if !ok {
		err = errors.New("Record not present")
		return
	}
	if err = pr.ValidatePassword(password); err != nil {
		return
	}

	// decrypt key
	var key []byte
	var rsaKey rsa.PrivateKey
	if pr.Type == AESRecord {
		key, err = pr.GetKeyAES(password)
		if err != nil {
			return
		}
	} else if pr.Type == RSARecord {
		rsaKey, err = pr.GetKeyRSA(password)
		if err != nil {
			return
		}
	} else {
		err = errors.New("Unkown record type")
		return
	}

	// add the password salt and hash
	if pr.PasswordSalt, err = makeRandom(16); err != nil {
		return
	}
	if pr.HashedPassword, err = hashPassword(newPassword, pr.PasswordSalt); err != nil {
		return
	}

	if pr.KeySalt, err = makeRandom(16); err != nil {
		return
	}
	newPassKey, err := derivePasswordKey(newPassword, pr.KeySalt)
	if err != nil {
		return
	}

	// encrypt original key with new password
	if pr.Type == AESRecord {
		pr.AESKey, err = encryptECB(key, newPassKey)
		if err != nil {
			return
		}
	} else if pr.Type == RSARecord {
		// encrypt RSA key with password key
		err = encryptRSARecord(&pr, &rsaKey, newPassKey)
		if err != nil {
			return
		}
	} else {
		err = errors.New("Unkown record type")
		return
	}

	SetRecord(pr, name)

	return WriteRecordsToDisk()
}

// DeleteRecord deletes a given record.
func DeleteRecord(name string) error {
	if _, ok := GetRecord(name); ok {
		delete(records.Passwords, name)
		return nil
	}

	return errors.New("Record missing")
}

// RevokeRecord removes admin status from a record.
func RevokeRecord(name string) error {
	if rec, ok := GetRecord(name); ok {
		rec.Admin = false
		SetRecord(rec, name)
		return nil
	}

	return errors.New("Record missing")
}

// MakeAdmin adds admin status to a given record.
func MakeAdmin(name string) error {
	if rec, ok := GetRecord(name); ok {
		rec.Admin = true
		SetRecord(rec, name)
		return nil
	}

	return errors.New("Record missing")
}

// SetRecord puts a record into the global status.
func SetRecord(pr PasswordRecord, name string) {
	records.Passwords[name] = pr
}

// GetRecord returns a record given a name.
func GetRecord(name string) (PasswordRecord, bool) {
	dpr, found := records.Passwords[name]
	return dpr, found
}

// GetVaultId returns the id of the current vault.
func GetVaultId() (id int, err error) {
	if !IsInitialized() {
		return 0, errors.New("Path not initialized")
	}

	return records.VaultId, nil
}

// GetHmacKey returns the hmac key of the current vault.
func GetHmacKey() (key []byte, err error) {
	if !IsInitialized() {
		return nil, errors.New("Path not initialized")
	}

	return records.HmacKey, nil
}

// IsInitialized returns true if the disk vault has been loaded.
func IsInitialized() bool {
	return localPath != ""
}

// NumRecords returns the number of records in the vault.
func NumRecords() int {
	return len(records.Passwords)
}

// GetSummary returns a summary of the records on disk.
func GetSummary() (summary map[string]Summary) {
	summary = make(map[string]Summary)
	for name, pass := range records.Passwords {
		summary[name] = Summary{pass.Admin, pass.Type}
	}
	return
}

// IsAdmin returns the admin status of the PasswordRecord.
func (pr PasswordRecord) IsAdmin() bool {
	return pr.Admin
}

// GetType returns the type status of the PasswordRecord.
func (pr PasswordRecord) GetType() string {
	return pr.Type
}

// EncryptKey encrypts a 16-byte key with the RSA key of the record.
func (pr PasswordRecord) EncryptKey(in []byte) (out []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, &pr.RSAKey.RSAPublic, in, nil)
}

// GetKeyAES returns the 16-byte key of the record.
func (pr PasswordRecord) GetKeyAES(password string) (key []byte, err error) {
	if pr.Type != AESRecord {
		return nil, errors.New("Invalid function for record type")
	}

	err = pr.ValidatePassword(password)
	if err != nil {
		return
	}

	passKey, err := derivePasswordKey(password, pr.KeySalt)
	if err != nil {
		return
	}

	return decryptECB(pr.AESKey, passKey)
}

// GetKeyAES returns the RSA public key of the record.
func (pr PasswordRecord) GetKeyRSAPub() (out *rsa.PublicKey, err error) {
	if pr.Type != RSARecord {
		return out, errors.New("Invalid function for record type")
	}
	return &pr.RSAKey.RSAPublic, err
}

// GetKeyAES returns the RSA private key of the record given the correct password.
func (pr PasswordRecord) GetKeyRSA(password string) (key rsa.PrivateKey, err error) {
	if pr.Type != RSARecord {
		return key, errors.New("Invalid function for record type")
	}

	err = pr.ValidatePassword(password)
	if err != nil {
		return
	}

	passKey, err := derivePasswordKey(password, pr.KeySalt)
	if err != nil {
		return
	}

	rsaExponentPadded, err := decryptCBC(pr.RSAKey.RSAExp, pr.RSAKey.RSAExpIV, passKey)
	if err != nil {
		return
	}
	rsaExponent, err := padding.RemovePadding(rsaExponentPadded)
	if err != nil {
		return
	}

	rsaPrimePPadded, err := decryptCBC(pr.RSAKey.RSAPrimeP, pr.RSAKey.RSAPrimePIV, passKey)
	if err != nil {
		return
	}
	rsaPrimeP, err := padding.RemovePadding(rsaPrimePPadded)
	if err != nil {
		return
	}

	rsaPrimeQPadded, err := decryptCBC(pr.RSAKey.RSAPrimeQ, pr.RSAKey.RSAPrimeQIV, passKey)
	if err != nil {
		return
	}
	rsaPrimeQ, err := padding.RemovePadding(rsaPrimeQPadded)
	if err != nil {
		return
	}

	key.PublicKey = pr.RSAKey.RSAPublic
	key.D = big.NewInt(0).SetBytes(rsaExponent)
	key.Primes = []*big.Int{big.NewInt(0), big.NewInt(0)}
	key.Primes[0].SetBytes(rsaPrimeP)
	key.Primes[1].SetBytes(rsaPrimeQ)

	err = key.Validate()
	if err != nil {
		return
	}

	return
}

// ValidatePassword returns an error if the password is incorrect.
func (pr PasswordRecord) ValidatePassword(password string) error {
	if h, err := hashPassword(password, pr.PasswordSalt); err != nil {
		return err
	} else {
		if bytes.Compare(h, pr.HashedPassword) != 0 {
			return errors.New("Wrong Password")
		}
	}

	return nil
}
