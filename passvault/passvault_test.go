// passvault_test: tests for passvault.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package passvault

import (
	"os"
	"testing"
)

func TestStaticVault(t *testing.T) {
	// Initial create.
	records, err := InitFrom("/tmp/redoctober.jso")
	if err != nil {
		t.Fatalf("Error reading record")
	}

	_, err = records.AddNewRecord("test", "bad pass", true, DefaultRecordType)
	if err != nil {
		t.Fatalf("Error creating record")
	}

	// Reads data written last time.
	_, err = InitFrom("/tmp/redoctober.json")
	if err != nil {
		t.Fatalf("Error reading record")
	}

	// Cleaning.
	os.Remove("/tmp/redoctober.json")
}

func TestRSAEncryptDecrypt(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	myRec, err := records.AddNewRecord("user", "weakpassword", true, RSARecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = myRec.GetKeyRSAPub()
	if err != nil {
		t.Fatalf("Error extracting RSA Pub")
	}

	rsaPriv, err := myRec.GetKeyRSA("mypasswordiswrong")
	if err == nil {
		t.Fatalf("Incorrect password did not fail")
	}

	rsaPriv, err = myRec.GetKeyRSA("weakpassword")
	if err != nil {
		t.Fatalf("Error decrypting RSA key")
	}

	err = rsaPriv.Validate()
	if err != nil {
		t.Fatalf("Error validating RSA key")
	}
}

func TestECCEncryptDecrypt(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	myRec, err := records.AddNewRecord("user", "weakpassword", true, ECCRecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = myRec.GetKeyECCPub()
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = myRec.GetKeyECC("mypasswordiswrong")
	if err == nil {
		t.Fatalf("Incorrect password did not fail")
	}

	_, err = myRec.GetKeyECC("weakpassword")
	if err != nil {
		t.Fatalf("%v", err)
	}
}
