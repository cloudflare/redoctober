// passvault_test: tests for passvault.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package passvault

import (
	"testing"
)

func TestRSAEncryptDecrypt(t *testing.T) {
	oldDefaultRecordType := DefaultRecordType
	DefaultRecordType = RSARecord
	myRec, err := createPasswordRec("mypasswordisweak", true)
	if err != nil {
		t.Fatalf("Error creating record")
	}

	_, err = myRec.GetKeyRSAPub()
	if err != nil {
		t.Fatalf("Error extracting RSA Pub")
	}

	rsaPriv, err := myRec.GetKeyRSA("mypasswordiswrong")
	if err == nil {
		t.Fatalf("Incorrect password did not fail")
	}

	rsaPriv, err = myRec.GetKeyRSA("mypasswordisweak")
	if err != nil {
		t.Fatalf("Error decrypting RSA key")
	}

	err = rsaPriv.Validate()
	if err != nil {
		t.Fatalf("Error validating RSA key")
	}
	DefaultRecordType = oldDefaultRecordType
}

func TestECCEncryptDecrypt(t *testing.T) {
	oldDefaultRecordType := DefaultRecordType
	DefaultRecordType = ECCRecord
	myRec, err := createPasswordRec("mypasswordisweak", true)
	if err != nil {
		t.Fatalf("Error creating record")
	}

	_, err = myRec.GetKeyECCPub()
	if err != nil {
		t.Fatalf("Error extracting EC pub")
	}

	_, err = myRec.GetKeyECC("mypasswordiswrong")
	if err == nil {
		t.Fatalf("Incorrect password did not fail")
	}

	_, err = myRec.GetKeyECC("mypasswordisweak")
	if err != nil {
		t.Fatalf("Error decrypting EC key")
	}
	DefaultRecordType = oldDefaultRecordType
}
