// cryptor_test.go: tests for core.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package cryptor

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
	"github.com/cloudflare/redoctober/persist"
)

func TestHash(t *testing.T) {
	decryptJson := []byte("{\"Version\":1,\"VaultId\":529853895,\"KeySet\":[{\"Name\":[\"Bob\",\"Alice\"],\"Key\":\"2j3tI2PBFBbwFX0BlQdUuA==\"},{\"Name\":[\"Bob\",\"Carol\"],\"Key\":\"yLSSB/U6+5rc1E+gjGXT4w==\"},{\"Name\":[\"Alice\",\"Bob\"],\"Key\":\"DDlWHF7szzISuXWaEz8llQ==\"},{\"Name\":[\"Alice\",\"Carol\"],\"Key\":\"TkA13aPrYFNbveIbl0qdww==\"},{\"Name\":[\"Carol\",\"Bob\"],\"Key\":\"KXm0uObmRJ2ZvSYEWPwk2A==\"},{\"Name\":[\"Carol\",\"Alice\"],\"Key\":\"L9c+PqtxPh9y6apRvtbCQw==\"}],\"KeySetRSA\":{\"Alice\":{\"Key\":\"fj5mqnq7y5KCafCGT1I51xI5JsX746+9TTSsp/8ybf3iZjhFzSlwP3aNmsOx3SUKTmZlfs+b+MeD4eKJ2uKBFzQHAIPO0fwoiCDKHhKH6KsolNq4+jgpkLAMOLsQGs8g6BhJy6bCFRjZVc3IdlQABPM6PkTbuSvKhn9atDFwZQD5TJBISi7d2hw4LradtLITbNqwiFMTQQ9+psXzyavY8H3LNHKGgf5Od7IpthEQPCHi4nw7X/YVRTEMfoIVcMcKOwYjlC45/VJEHK9Zy3DSiLBzjmr57YNIVjw8YZY5DGBWqbgu51RUbIcrqyLphBhXoBRu4R+yrhygBNWbvkkifA==\"},\"Bob\":{\"Key\":\"HTYiZ18sf721cAN1LRNkJ/+L4AKWilMrkMyNiBjWcl9HRTVPNXITqQBXd0fBggGNPiZr6VQTySK4ZFvJKGDGiz17Te/ToDn8Yk/B9cqMsN5fHoQtXvl8IZo2wioA67ccAJ1gHMMNpPyLdF43SQqgI+XaQ2lMSYLMfxxDmBBOQ1SWAto0BDRdnsqpwUwIPKQ9Y3/1osmrjLmJoAC3MPplexYWhexNwJtSd+mFdVZ3Qe4x9RsRHcN/myihOt/67V60qzs13F0RZkMSDzj5Ddg+1KVNJZY9dmolPNkAZj8z20L9uzpatrTYTR6A8q/sRn+inO7ZQVQ00XO6q6lYYQzxnw==\"},\"Carol\":{\"Key\":\"ItrvS02nSfbcA2fl1L1i61xqPEDKRdsrYe3+UCbkT+ipheiQRPSuikbzeV2kshn4yJDeku5bmTNqW8HSGtU7GTgCoIWV8WmEf4w6ovzShPbu+VrIZvRz3wjh2oYHT/gtPVAQnBa/71FeoBNxy5l/hBcUmBky43j83Mlt2+8QZx6PEUDmpaPQemVh99+C20nQtkAUFeMc2Ge4y7RlHSxtfABvwlXx1NzCD40nyJfF1SjV/fZh/E2Al4Tavx6DOJkYGoJ2mp7XBvX0IF2tp8T3U5VpnTek/WuNrLL9z7/jqzWh87lZ5KheWXhGkU1BNH4lfIj43pDkSy50aDvS0zYfHQ==\"}},\"IV\":\"58r9Mz8e06mItBG9nSV/0Q==\",\"Data\":\"QE9ZhcGXNXauUdMk04biUGy1SoP5H2nF/j2JjiiVFKPdIdRp/Gc+AZvUI9n22ZM4q+zDiJz7qvK4bKaPpXhTmGP0XheaFUukeVNS9STMoTbNcY/ZtVOz6hizUPF7gSq388QPUsT+Axml3rEUTWOhnw==\",\"Signature\":\"ItiAS26GFlbM5szJr5HXVB9BR+s=\"}")

	var encrypted EncryptedData
	if err := json.Unmarshal(decryptJson, &encrypted); err != nil {
		t.Fatalf("Error unmarshalling json, %v", err)
	}

	var hmacKey, _ = base64.StdEncoding.DecodeString("Qugc5ZQ0vC7KQSgmDHTVgQ==")
	var signature = append([]byte{}, encrypted.Signature...)

	expectedSig := encrypted.computeHmac(hmacKey)

	if diff := bytes.Compare(signature, expectedSig); diff != 0 {
		t.Fatalf("Error comparing signature %v", base64.StdEncoding.EncodeToString(expectedSig))
	}

	// change version and check hmac
	encrypted.Version = 2
	unexpectedSig := encrypted.computeHmac(hmacKey)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}
	encrypted.Version = 1

	// change vaultid and check hmac
	encrypted.VaultId = 529853896
	unexpectedSig = encrypted.computeHmac(hmacKey)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}
	encrypted.VaultId = 529853895

	// swap two records and check hmac
	encrypted.KeySet[0], encrypted.KeySet[1] = encrypted.KeySet[1], encrypted.KeySet[0]
	unexpectedSig = encrypted.computeHmac(hmacKey)

	if diff := bytes.Compare(signature, unexpectedSig); diff != 0 {
		t.Fatalf("Error comparing signature %v, %v",
			base64.StdEncoding.EncodeToString(unexpectedSig),
			base64.StdEncoding.EncodeToString(signature))
	}

	// delete RSA key and check hmac
	encrypted.Version = 1
	delete(encrypted.KeySetRSA, "Carol")
	unexpectedSig = encrypted.computeHmac(hmacKey)

	if diff := bytes.Compare(signature, unexpectedSig); diff == 0 {
		t.Fatalf("Error comparing signature")
	}

}

func TestDuplicates(t *testing.T) {
	// Setup total names and partitions.
	names := []string{"Alice", "Bob", "Carl"}
	recs := make(map[string]passvault.PasswordRecord, 0)
	left := []string{"Alice", "Bob"}
	right := []string{"Bob", "Carl"}

	// Add each user to the keycache.
	cache := keycache.NewCache()
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cfg := &config.Delegations{Persist: false}
	store, err := persist.New(cfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	c := Cryptor{&records, &cache, store}

	for _, name := range names {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		recs[name] = pr
	}

	// Create candidate encryption of message.
	ac := AccessStructure{
		LeftNames:  left,
		RightNames: right,
	}

	resp, err := c.Encrypt([]byte("Hello World!"), []string{}, ac)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	// Delegate one key at a time and check that decryption fails.
	for name, pr := range recs {
		err = cache.AddKeyFromRecord(pr, name, "weakpassword", nil, nil, 2, "", "1h")
		if err != nil {
			t.Fatalf("%v", err)
		}

		_, _, _, _, err := c.Decrypt(resp, name)
		if err == nil {
			t.Fatalf("That shouldn't have worked!")
		}

		cache.Flush()
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// Setup total names and partitions.
	names := []string{"Alice", "Bob", "Carl"}
	recs := make(map[string]passvault.PasswordRecord, 0)
	left := []string{"Alice", "Bob"}
	right := []string{"Bob", "Carl"}

	// Add each user to the keycache.
	cache := keycache.NewCache()
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	cfg := &config.Delegations{Persist: false}
	store, err := persist.New(cfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	c := Cryptor{&records, &cache, store}

	for _, name := range names {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		recs[name] = pr
	}

	// Create candidate encryption of message.
	ac := AccessStructure{
		LeftNames:  left,
		RightNames: right,
	}

	resp, err := c.Encrypt([]byte("Hello World!"), []string{}, ac)
	if err != nil {
		t.Fatalf("Error: %s", err)
	}

	// Delegate all the things.
	for name, pr := range recs {
		err = cache.AddKeyFromRecord(pr, name, "weakpassword", nil, nil, 2, "", "1h")
		if err != nil {
			t.Fatalf("%v", err)
		}
	}

	// (resp []byte, labels, names []string, secure bool, err error)
	_, _, _, _, err = c.Decrypt(resp, "alice")
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func tempName() (string, error) {
	tmpf, err := ioutil.TempFile("", "ro_cryptor")
	if err != nil {
		return "", err
	}

	name := tmpf.Name()
	tmpf.Close()
	return name, nil
}

func TestRestore(t *testing.T) {
	const testUses = 5 // How many uses to delegate for.

	// Get the temporary persisted file.
	temp, err := tempName()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(temp)

	// Setup total names and partitions.
	names := []string{"Alice", "Bob", "Carl"}
	recs := make(map[string]passvault.PasswordRecord, 0)

	// Add each user to the keycache.
	cache := keycache.NewCache()
	records, err := passvault.InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	for _, name := range names {
		pr, err := records.AddNewRecord(name, "weakpassword", true, passvault.DefaultRecordType)
		if err != nil {
			t.Fatalf("%v", err)
		}

		recs[name] = pr
	}

	alice, ok := records.GetRecord("Alice")
	if !ok {
		t.Fatal("Alice not found in password vault.")
	}

	carl, ok := records.GetRecord("Carl")
	if !ok {
		t.Fatal("Carl not found in password vault.")
	}

	// First, simulate a running Red October with persistence.
	cfg := &config.Delegations{
		Persist:   true,
		Mechanism: persist.FileMechanism,
		Location:  temp,
		Policy:    "(Alice & Bob) | (Bob & Carl)",
		Users:     []string{"Alice", "Bob", "Carl"},
	}

	store, err := persist.New(cfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	c := Cryptor{&records, &cache, store}
	c.persist.Persist()

	err = c.Delegate(alice, "Alice", "weakpassword", []string{"Bob"}, []string{},
		testUses, "", "1h")
	if err != nil {
		t.Fatal(err)
	}

	err = c.Delegate(carl, "Carl", "weakpassword", []string{"Bob"}, []string{},
		testUses, "", "1h")

	// Next, simulate restarting that server.
	store, err = persist.New(cfg)
	if err != nil {
		t.Fatal(err.Error())
	}

	c = Cryptor{&records, &cache, store}
	if _, err := os.Stat(temp); err != nil {
		t.Fatalf("Not persisting: %v", err)
	}

	err = c.Restore("Alice", "weakpassword", 2, "", "1h")
	if err != ErrRestoreDelegations {
		t.Fatal(err)
	}

	err = c.Restore("Carl", "weakpassword", 2, "", "1h")
	if err != ErrRestoreDelegations {
		t.Fatal(err)
	}

	status := c.Status()
	if status.State != persist.Inactive {
		t.Fatalf("The persistent delegations should be %s, not %s",
			persist.Inactive, status.State)
	}

	err = c.Restore("Carl", "weakpassword", 0, "", "0h")
	if err != ErrRestoreDelegations {
		t.Fatal(err)
	}

	err = c.Restore("Bob", "weakpassword", 2, "", "1h")
	if err != nil {
		t.Fatal(err)
	}

	status = c.Status()
	if status.State != persist.Active {
		t.Fatalf("The persistent delegations should be %s, not %s",
			persist.Active, status.State)
	}

	if len(c.cache.UserKeys) != 2 {
		t.Fatal("Delegations do not seem to have been restored.")
	}

	usage, ok := c.cache.UserKeys[keycache.DelegateIndex{Name: "Alice"}]
	if !ok {
		t.Fatal("Alice not found in active delegations.")
	}

	if usage.Uses != testUses {
		t.Fatal("Invalid number of uses in restored delegations.")
	}

	usage, ok = c.cache.UserKeys[keycache.DelegateIndex{Name: "Carl"}]
	if !ok {
		t.Fatal("Carl not found in active delegations.")
	}

	if usage.Uses != testUses {
		t.Fatal("Invalid number of uses in restored delegations.")
	}

	_, ok = c.cache.UserKeys[keycache.DelegateIndex{Name: "Bob"}]
	if ok {
		t.Fatal("Bob shouldn't be in the active delegations.")
	}

}
