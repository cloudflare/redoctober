// Package passvault manages the vault containing user records on disk.
package passvault

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/sha1"
	"crypto/aes"
	"crypto/rsa"
	"crypto/rand"
	"crypto/cipher"
	mrand "math/rand"
	"math/big"
	"io/ioutil"
	"encoding/json"
	"bytes"
	"encoding/binary"
	"errors"
	"redoctober/padding"
)

// Constants for record type.
const (
	AESRecord = "AES"
	RSARecord = "RSA"
	ECCRecord = "ECC"
)

// Constants for scrypt.
const (
	KEYLENGTH = 16
	N         = 16384
	R         = 8
	P         = 1

	DEFAULT_VERSION = 1
)


// Set of encrypted records from disk
var records diskRecords
// Path of current vault
var localPath string

// DiskPasswordRecord is the set of password records on disk.
type DiskPasswordRecord struct {
	Type string
	Salt []byte
	HashedPassword []byte
	KeySalt []byte
	AESKey []byte
	RSAKey struct {
		RSAExp []byte
		RSAExpIV []byte
		RSAPrimeP []byte
		RSAPrimePIV []byte
		RSAPrimeQ []byte
		RSAPrimeQIV []byte
		RSAPublic rsa.PublicKey
	}
	Admin bool
}
type diskRecords struct {
	Version int
	VaultId int
	HmacKey []byte
	Passwords map[string]DiskPasswordRecord
}

// Summary is a minmal account summary.
type Summary struct {
	Admin bool
	Type string
}

// Intialization.
func init() {
	// seed math.random from crypto.random
	seedBytes, _ := makeRandom(8)
	seedBuf := bytes.NewBuffer(seedBytes)
	n64, _ := binary.ReadVarint(seedBuf)
	mrand.Seed(n64)

}

// Take a password and derive a scrypt hashed version
func hashPassword(password string, salt []byte) (hashPass []byte, err error) {
	return scrypt.Key([]byte(password), salt, N, R, P, KEYLENGTH)
}

// Helper to make new buffer full of random data
func makeRandom(length int) (bytes []byte, err error) {
	bytes = make([]byte, 16)
	n, err := rand.Read(bytes)
	if n != len(bytes) || err != nil {
		return
	}
	return
}

func encryptRSARecord(newRec *DiskPasswordRecord, rsaPriv *rsa.PrivateKey, passKey []byte) (err error) {
	newRec.RSAKey.RSAExpIV, err = makeRandom(16)
	if err != nil {
		return
	}

	paddedExponent := padding.PadClearFile(rsaPriv.D.Bytes())
	newRec.RSAKey.RSAExp, err = encryptCBC(paddedExponent, newRec.RSAKey.RSAExpIV, passKey)
	if err != nil {
		return
	}

	newRec.RSAKey.RSAPrimePIV, err = makeRandom(16)
	if err != nil {
		return
	}

	paddedPrimeP := padding.PadClearFile(rsaPriv.Primes[0].Bytes())
	newRec.RSAKey.RSAPrimeP, err = encryptCBC(paddedPrimeP, newRec.RSAKey.RSAPrimePIV, passKey)
	if err != nil {
		return
	}

	newRec.RSAKey.RSAPrimeQIV, err = makeRandom(16)
	if err != nil {
		return
	}

	paddedPrimeQ := padding.PadClearFile(rsaPriv.Primes[1].Bytes())
	newRec.RSAKey.RSAPrimeQ, err = encryptCBC(paddedPrimeQ, newRec.RSAKey.RSAPrimeQIV, passKey)
	if err != nil {
		return
	}
	return
}

// Create new record from username and password
func createPasswordRec(password string, admin bool) (newRec DiskPasswordRecord, err error) {
	newRec.Type = RSARecord

	newRec.Salt, err = makeRandom(16)
	if err != nil {
		return
	}

	newRec.HashedPassword, err = hashPassword(password, newRec.Salt)
	if err != nil {
		return
	}

	newRec.KeySalt, err = makeRandom(16)
	if err != nil {
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
	err = encryptRSARecord(&newRec, rsaPriv, passKey)
	if err != nil {
		return
	}

	newRec.RSAKey.RSAPublic = rsaPriv.PublicKey

	// encrypt AES key with password key
	aesKey, err := makeRandom(16)
	if err != nil {
		return
	}

	newRec.AESKey, err = encryptECB(aesKey, passKey)
	if err != nil {
		return
	}

	newRec.Admin = admin

	return
}

func derivePasswordKey(password string, keySalt []byte) (passwordKey []byte, err error) {
	return scrypt.Key([]byte(password), keySalt, N, R, P, KEYLENGTH)
}

// Decrypt bytes using a key in ECB mode.
func decryptECB(data []byte, passwordKey []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(passwordKey)
	if err != nil {
		return
	}

	decryptedData = make([]byte, len(data))
	aesCrypt.Decrypt(decryptedData, data)

	return
}

// Decrypt bytes using a key in ECB mode.
func encryptECB(data []byte, passwordKey []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(passwordKey)
	if err != nil {
		return
	}

	encryptedData = make([]byte, len(data))
	aesCrypt.Encrypt(encryptedData, data)

	return
}

// Decrypt using a key and IV.
func decryptCBC(data []byte, iv []byte, passwordKey []byte) (decryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(passwordKey)
	if err != nil {
		return
	}
	ivBytes := append([]byte{}, iv...)

	decryptedData = make([]byte, len(data))
	aesCBC := cipher.NewCBCDecrypter(aesCrypt, ivBytes)
	aesCBC.CryptBlocks(decryptedData, data)

	return
}

// Encrypt using a key and IV.
func encryptCBC(data []byte, iv []byte, passwordKey []byte) (encryptedData []byte, err error) {
	aesCrypt, err := aes.NewCipher(passwordKey)
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
func InitFromDisk(path string) {
	jsonDiskRecord, err := ioutil.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(jsonDiskRecord, &records)
	}

	// validate sizes
	formatErr := false
	for _, rec := range records.Passwords {
		if len(rec.Salt) != 16 {
			formatErr = true
		}
		if len(rec.HashedPassword) != 16 {
			formatErr = true
		}
		if len(rec.KeySalt) != 16 {
			formatErr = true
		}
		if rec.Type == AESRecord {
			if len(rec.AESKey) != 16 {
				formatErr = true
			}
		}
		if rec.Type == RSARecord {
			if len(rec.RSAKey.RSAExp) == 0 || len(rec.RSAKey.RSAExp) % 16 != 0 {
				formatErr = true
			}
			if len(rec.RSAKey.RSAPrimeP) == 0 || len(rec.RSAKey.RSAPrimeP) % 16 != 0 {
				formatErr = true
			}
			if len(rec.RSAKey.RSAPrimeQ) == 0 || len(rec.RSAKey.RSAPrimeQ) % 16 != 0 {
				formatErr = true
			}
			if len(rec.RSAKey.RSAExpIV) != 16  {
				formatErr = true
			}
			if len(rec.RSAKey.RSAPrimePIV) != 16  {
				formatErr = true
			}
			if len(rec.RSAKey.RSAPrimeQIV) != 16  {
				formatErr = true
			}
		}
		if formatErr {
			err = errors.New("Format error")
			break
		}
	}

	if err != nil {
		records.Version = DEFAULT_VERSION
		records.VaultId = mrand.Int()
		records.HmacKey, err = makeRandom(16)
		if err != nil {
			return
		}
		// make the record data holder
		records.Passwords = make(map[string]DiskPasswordRecord)
	}

	localPath = path
}

// WriteRecordsToDisk saves the current state of the records to disk.
func WriteRecordsToDisk() (err error) {
	if !IsInitialized() {
		err = errors.New("Path not initialized")
		return
	}

	jsonDiskRecord, err := json.Marshal(records)
	if err == nil {
		err = ioutil.WriteFile(localPath, jsonDiskRecord, 0644)
	}

	return
}

// AddNewRecord adds a new record for a given username and password.
func AddNewRecord(name string, password string, admin bool) (passwordRec DiskPasswordRecord, err error) {
	passwordRec, err = createPasswordRec(password, admin)
	if err != nil {
		return
	}

	SetRecord(passwordRec, name)

	err = WriteRecordsToDisk()
	if err != nil {
		return
	}

	return
}

// ChangePassword changes the password for a given user.
func ChangePassword(name string, password string, newPassword string) (err error) {
	// find and validate name and password
	passwordRec, ok := GetRecord(name)
	if !ok {
		err = errors.New("Record not present")
		return
	}
	err = passwordRec.ValidatePassword(password)
	if err != nil {
		return
	}

	// decrypt key
	var key []byte
	var rsaKey rsa.PrivateKey
	if passwordRec.Type == AESRecord {
		key, err = passwordRec.GetKeyAES(password)
		if err != nil {
			return
		}
	} else if passwordRec.Type == RSARecord {
		rsaKey, err = passwordRec.GetKeyRSA(password)
		if err != nil {
			return
		}
	} else {
		err = errors.New("Unkown record type")
		return
	}

	// create new salt
	passwordRec.Salt, err = makeRandom(16)
	if err != nil {
		return
	}

	// hash new password
	passwordRec.HashedPassword, err = hashPassword(newPassword, passwordRec.Salt)
	if err != nil {
		return
	}

	// create new key salt
	passwordRec.KeySalt, err = makeRandom(16)
	if err != nil {
		return
	}

	newPassKey, err := derivePasswordKey(newPassword, passwordRec.KeySalt)
	if err != nil {
		return
	}

	// encrypt original key with new password
	if passwordRec.Type == AESRecord {
		passwordRec.AESKey, err = encryptECB(key, newPassKey)
		if err != nil {
			return
		}
	} else if passwordRec.Type == RSARecord {
	// encrypt RSA key with password key
		err = encryptRSARecord(&passwordRec, &rsaKey, newPassKey)
		if err != nil {
			return
		}
	} else {
		err = errors.New("Unkown record type")
		return
	}

	SetRecord(passwordRec, name)

	// update disk record
	err = WriteRecordsToDisk()
	if err != nil {
		return
	}

	return
}

// DeleteRecord deletes a given record.
func DeleteRecord(name string) error {
	if _, ok := GetRecord(name); ok {
		delete(records.Passwords, name)
	} else {
		return errors.New("Record missing")
	}
	return nil
}

// RevokeRecord removes admin status from a record.
func RevokeRecord(name string) error {
	rec, ok := GetRecord(name)
	if ok {
		rec.Admin = false
		SetRecord(rec, name)
	} else {
		return errors.New("Record missing")
	}
	return nil
}

// MakeAdmin adds admin status to a given record.
func MakeAdmin(name string) error {
	rec, ok := GetRecord(name)
	if ok {
		rec.Admin = true
		SetRecord(rec, name)
	} else {
		return errors.New("Record missing")
	}
	return nil
}

// SetRecord puts a record into the global status.
func SetRecord(passwordRec DiskPasswordRecord, name string) {
	records.Passwords[name] = passwordRec
}

// GetRecord returns a record given a name.
func GetRecord(name string) (passwordRec DiskPasswordRecord, ok bool) {
	passwordRec, ok = records.Passwords[name]
	return
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
		tempName := Summary{pass.Admin, pass.Type}
		summary[name] = tempName
	}
	return
}

// IsAdmin returns the admin status of the DiskPasswordRecord.
func (passwordRec DiskPasswordRecord) IsAdmin() bool {
	return passwordRec.Admin
}

// GetType returns the type status of the DiskPasswordRecord.
func (passwordRec DiskPasswordRecord) GetType() string {
	return passwordRec.Type
}

// EncryptKey encrypts a 16-byte key with the RSA key of the record.
func (passwordRec DiskPasswordRecord) EncryptKey(in []byte) (out []byte, err error) {
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, &passwordRec.RSAKey.RSAPublic, in, nil)
}

// GetKeyAES returns the 16-byte key of the record.
func (passwordRec DiskPasswordRecord) GetKeyAES(password string) (key []byte, err error) {
	if passwordRec.Type != AESRecord {
		return nil, errors.New("Invalid function for record type")
	}

	err = passwordRec.ValidatePassword(password)
	if err != nil {
		return
	}

	passKey, err := derivePasswordKey(password, passwordRec.KeySalt)
	if err != nil {
		return
	}

	return decryptECB(passwordRec.AESKey, passKey)
}

// GetKeyAES returns the RSA public key of the record.
func (passwordRec DiskPasswordRecord) GetKeyRSAPub() (out *rsa.PublicKey, err error) {
	if passwordRec.Type != RSARecord {
		return out, errors.New("Invalid function for record type")
	}
	return &passwordRec.RSAKey.RSAPublic, err
}

// GetKeyAES returns the RSA private key of the record given the correct password.
func (passwordRec DiskPasswordRecord) GetKeyRSA(password string) (key rsa.PrivateKey, err error) {
	if passwordRec.Type != RSARecord {
		return key, errors.New("Invalid function for record type")
	}

	err = passwordRec.ValidatePassword(password)
	if err != nil {
		return
	}

	passKey, err := derivePasswordKey(password, passwordRec.KeySalt)
	if err != nil {
		return
	}

	rsaExponentPadded, err := decryptCBC(passwordRec.RSAKey.RSAExp, passwordRec.RSAKey.RSAExpIV, passKey)
	if err != nil {
		return
	}
	rsaExponent, err := padding.RemovePadding(rsaExponentPadded)
	if err != nil {
		return
	}

	rsaPrimePPadded, err := decryptCBC(passwordRec.RSAKey.RSAPrimeP, passwordRec.RSAKey.RSAPrimePIV, passKey)
	if err != nil {
		return
	}
	rsaPrimeP, err := padding.RemovePadding(rsaPrimePPadded)
	if err != nil {
		return
	}

	rsaPrimeQPadded, err := decryptCBC(passwordRec.RSAKey.RSAPrimeQ, passwordRec.RSAKey.RSAPrimeQIV, passKey)
	if err != nil {
		return
	}
	rsaPrimeQ, err := padding.RemovePadding(rsaPrimeQPadded)
	if err != nil {
		return
	}

	key.PublicKey = passwordRec.RSAKey.RSAPublic
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
func (passwordRec DiskPasswordRecord) ValidatePassword(password string) (err error) {
	sha, err := hashPassword(password, passwordRec.Salt)
	if err != nil {
		return
	}

	if bytes.Compare(sha, passwordRec.HashedPassword) != 0 {
		return errors.New("Wrong Password")
	}
	return
}

