// passvault_test: tests for passvault.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package passvault

import (
	"os"
	"testing"
)

func TestStaticVault(t *testing.T) {
	// Creates a temporary on-disk database to test if passvault can read and
	// write from/to disk.  It's deleted at the bottom of the function--this
	// should be the only test that requires touching disk.
	records, err := InitFrom("/tmp/redoctober.json")
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

func TestChangePassword(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = records.AddNewRecord("user", "weakpassword", true, ECCRecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = records.ChangePassword("user", "weakpassword", "newpassword")
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = records.AddNewRecord("user2", "weakpassword", true, RSARecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = records.ChangePassword("user2", "weakpassword", "newpassword")
	if err != nil {
		t.Fatalf("%v", err)
	}
}

func TestDeleteRecord(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, err = records.AddNewRecord("user", "weakpassword", true, ECCRecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = records.DeleteRecord("user")
	if err != nil {
		t.Fatalf("%v", err)
	}

	_, retVal := records.GetRecord("user")
	if retVal == true {
		t.Fatalf("Record not deleting properly")
	}
}

func TestMakeRevokeAdmin(t *testing.T) {
	records, err := InitFrom("memory")
	if err != nil {
		t.Fatalf("%v", err)
	}

	myRec, err := records.AddNewRecord("user", "weakpassword", false, ECCRecord)
	if err != nil {
		t.Fatalf("%v", err)
	}

	err = records.MakeAdmin("user")
	if err != nil {
		t.Fatalf("%v", err)
	}

	myRec, _ = records.GetRecord("user")
	retval := myRec.IsAdmin()
	if retval != true {
		t.Fatalf("Incorrect Admin value")
	}

	err = records.RevokeRecord("user")
	if err != nil {
		t.Fatalf("%v", err)
	}

	myRec, _ = records.GetRecord("user")
	retval = myRec.IsAdmin()
	if retval != false {
		t.Fatalf("Incorrect Admin value")
	}

}
