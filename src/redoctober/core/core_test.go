// core_test.go: tests for core.go
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"testing"
	"os"
	"redoctober/passvault"
	"redoctober/keycache"
	"redoctober/keycache"
	"redoctober/passvault"
)

func TestCreate(t *testing.T) {
	createJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\"}")

	os.Remove("/tmp/db1.json")
	Init("/tmp/db1.json")

	respJson, err := Create(createJson)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}

	var s responseData
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in creating account, ", s.Status)
	}

	// check to see if creation can happen twice
	respJson, err = Create(createJson)
	if err != nil {
		t.Fatalf("Error in creating account when one exists, ", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account when one exists, ", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in creating account when one exists, ", s.Status)
	}

	os.Remove("/tmp/db1.json")
}

func TestSummary(t *testing.T) {
	createJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\"}")
	delegateJson := []byte("{\"Name\":\"Bob\",\"Password\":\"Rob\",\"Time\":\"2h\",\"Uses\":1}")
	os.Remove("/tmp/db1.json")

	// check for summary of uninitialized vault
	respJson, err := Summary(createJson)
	if err != nil {
		t.Fatalf("Error in summary of account with no vault,", err)
	}
	var s summaryData
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in summary of account with no vault,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in summary of account with no vault, ", s.Status)
	}

	Init("/tmp/db1.json")

	// check for summary of initialized vault
	respJson, err = Create(createJson)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in creating account, ", s.Status)
	}

	respJson, err = Summary(createJson)
	if err != nil {
		t.Fatalf("Error in summary of account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in summary of account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in summary of account, ", s.Status)
	}

	data, ok := s.All["Alice"]
	if !ok {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if data.Admin != true {
		t.Fatalf("Error in summary of account, record incorrect ")
	}
	if data.Type != passvault.RSARecord {
		t.Fatalf("Error in summary of account, record incorrect ")
	}

	// check for summary of initialized vault with new member
	respJson, err = Delegate(delegateJson)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Summary(createJson)
	if err != nil {
		t.Fatalf("Error in summary of account with no vault,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in summary of account with no vault,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in summary of account with no vault, ", s.Status)
	}

	data, ok = s.All["Alice"]
	if !ok {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if data.Admin != true {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if data.Type != passvault.RSARecord {
		t.Fatalf("Error in summary of account, record missing ")
	}

	data, ok = s.All["Bob"]
	if !ok {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if data.Admin != false {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if data.Type != passvault.RSARecord {
		t.Fatalf("Error in summary of account, record missing ")
	}

	dataLive, ok := s.Live["Bob"]
	if !ok {
		t.Fatalf("Error in summary of account, record missing", keycache.UserKeys)
	}
	if dataLive.Admin != false {
		t.Fatalf("Error in summary of account, record missing ")
	}
	if dataLive.Type != passvault.RSARecord {
		t.Fatalf("Error in summary of account, record missing ")
	}

	keycache.FlushCache()

	os.Remove("/tmp/db1.json")
}

func TestPassword(t *testing.T) {
	createJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\"}")
	delegateJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"Time\":\"2h\",\"Uses\":1}")
	passwordJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"NewPassword\":\"Olleh\"}")
	delegateJson2 := []byte("{\"Name\":\"Alice\",\"Password\":\"Olleh\",\"Time\":\"2h\",\"Uses\":1}")
	passwordJson2 := []byte("{\"Name\":\"Alice\",\"Password\":\"Olleh\",\"NewPassword\":\"Hello\"}")
	os.Remove("/tmp/db1.json")

	Init("/tmp/db1.json")

	// check for summary of initialized vault with new member
	var s responseData
	respJson, err := Create(createJson)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account, ", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in creating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Password(passwordJson2)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in password, ", s.Status)
	}

	respJson, err = Password(passwordJson)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in password, ", s.Status)
	}

	respJson, err = Delegate(delegateJson)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson2)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Password(passwordJson2)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in password", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in password, ", s.Status)
	}

	respJson, err = Delegate(delegateJson)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	keycache.FlushCache()

	os.Remove("/tmp/db1.json")
}

func TestEncryptDecrypt(t *testing.T) {
	summaryJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\"}")
	delegateJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	delegateJson2 := []byte("{\"Name\":\"Bob\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	delegateJson3 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	delegateJson4 := []byte("{\"Name\":\"Bob\",\"Password\":\"Hello\",\"Time\":\"10s\",\"Uses\":2}")
	delegateJson5 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"Time\":\"10s\",\"Uses\":2}")
	encryptJson := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"Minumum\":2,\"Owners\":[\"Alice\",\"Bob\",\"Carol\"],\"Data\":\"SGVsbG8gSmVsbG8=\"}")
	encryptJson2 := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"Minumum\":2,\"Owners\":[\"Alice\",\"Bob\",\"Carol\"],\"Data\":\"SGVsbG8gSmVsbG8=\"}")
	os.Remove("/tmp/db1.json")

	Init("/tmp/db1.json")

	// check for summary of initialized vault with new member
	var s responseData
	respJson, err := Create(delegateJson)
	if err != nil {
		t.Fatalf("Error in creating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in creating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson2)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson3)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	// check summary to see if none are delegated
	keycache.Refresh()
	respJson, err = Summary(summaryJson)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	var sum summaryData
	err = json.Unmarshal(respJson, &sum)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum.Status != "ok" {
		t.Fatalf("Error in summary, ", sum.Status)
	}
	if len(sum.Live) != 0 {
		t.Fatalf("Error in summary, ", sum.Status)
	}

	// Encrypt with non-admin (fail)
	respJson, err = Encrypt(encryptJson)
	if err != nil {
		t.Fatalf("Error in encrypt,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in encrypt,", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in encrypt, ", s.Status)
	}

	// Encrypt
	respJson, err = Encrypt(encryptJson2)
	if err != nil {
		t.Fatalf("Error in encrypt,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in encrypt,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in encrypt, ", s.Status)
	}

	// decrypt file
	decryptJson, err := json.Marshal(decrypt{Name:"Alice", Password:"Hello", Data:s.Response})
	if err != nil {
		t.Fatalf("Error in marshalling decryption,", err)
	}

	respJson2, err := Decrypt(decryptJson)
	if err != nil {
		t.Fatalf("Error in decrypt,", err)
	}
	err = json.Unmarshal(respJson2, &s)
	if err != nil {
		t.Fatalf("Error in decrypt,", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in decrypt, ", s.Status)
	}

	// delegate two valid decryptors
	respJson, err = Delegate(delegateJson4)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson5)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	// verify the presence of the two delgations
	keycache.Refresh()
	var sum2 summaryData
	respJson, err = Summary(summaryJson)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	err = json.Unmarshal(respJson, &sum2)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum2.Status != "ok" {
		t.Fatalf("Error in summary, ", sum2.Status)
	}
	if len(sum2.Live) != 2 {
		t.Fatalf("Error in summary, ", sum2.Live)
	}

	respJson2, err = Decrypt(decryptJson)
	if err != nil {
		t.Fatalf("Error in decrypt,", err)
	}
	err = json.Unmarshal(respJson2, &s)
	if err != nil {
		t.Fatalf("Error in decrypt,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in decrypt, ", s.Status)
	}
	if string(s.Response) != "Hello Jello" {
		t.Fatalf("Error in decrypt, ", string(s.Response))
	}

	keycache.FlushCache()

	os.Remove("/tmp/db1.json")
}

func TestModify(t *testing.T) {
	summaryJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\"}")
	summaryJson2 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\"}")
	delegateJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	delegateJson2 := []byte("{\"Name\":\"Bob\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	delegateJson3 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"Time\":\"0s\",\"Uses\":0}")
	modifyJson := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"ToModify\":\"Alice\",\"Command\":\"admin\"}")
	modifyJson2 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"ToModify\":\"Alice\",\"Command\":\"revoke\"}")
	modifyJson3 := []byte("{\"Name\":\"Alice\",\"Password\":\"Hello\",\"ToModify\":\"Carol\",\"Command\":\"admin\"}")
	modifyJson4 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"ToModify\":\"Alice\",\"Command\":\"revoke\"}")
	modifyJson5 := []byte("{\"Name\":\"Carol\",\"Password\":\"Hello\",\"ToModify\":\"Alice\",\"Command\":\"delete\"}")

	os.Remove("/tmp/db1.json")
	Init("/tmp/db1.json")

	// check for summary of initialized vault with new member
	var s responseData
	respJson, err := Create(delegateJson)
	if err != nil {
		t.Fatalf("Error in creating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in creating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in creating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson2)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	respJson, err = Delegate(delegateJson3)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in delegating account,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in delegating account, ", s.Status)
	}

	// check summary to see if none are delegated
	keycache.Refresh()
	respJson, err = Summary(summaryJson)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	var sum summaryData
	err = json.Unmarshal(respJson, &sum)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum.Status != "ok" {
		t.Fatalf("Error in summary, ", sum.Status)
	}
	if len(sum.Live) != 0 {
		t.Fatalf("Error in summary, ", sum.Status)
	}

	// Modify from non-admin (fail)
	respJson, err = Modify(modifyJson)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in modify, ", s.Status)
	}

	// Modify self from admin (fail)
	respJson, err = Modify(modifyJson2)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	if s.Status == "ok" {
		t.Fatalf("Error in modify, ", s.Status)
	}

	// Modify admin from admin
	respJson, err = Modify(modifyJson3)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in modify, ", s.Status)
	}

	respJson, err = Summary(summaryJson)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	err = json.Unmarshal(respJson, &sum)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum.Status != "ok" {
		t.Fatalf("Error in summary, ", sum.Status)
	}
	if sum.All["Carol"].Admin != true {
		t.Fatalf("Error in summary, ", sum.All)
	}

	// Revoke admin from admin
	respJson, err = Modify(modifyJson4)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in modify, ", s.Status)
	}

	respJson, err = Summary(summaryJson2)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	err = json.Unmarshal(respJson, &sum)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum.Status != "ok" {
		t.Fatalf("Error in summary, ", sum.Status)
	}
	if sum.All["Alice"].Admin == true {
		t.Fatalf("Error in summary, ", sum.All)
	}

	// Delete from admin
	respJson, err = Modify(modifyJson5)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	err = json.Unmarshal(respJson, &s)
	if err != nil {
		t.Fatalf("Error in modify,", err)
	}
	if s.Status != "ok" {
		t.Fatalf("Error in modify, ", s.Status)
	}

	var sum3 summaryData
	respJson, err = Summary(summaryJson2)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	err = json.Unmarshal(respJson, &sum3)
	if err != nil {
		t.Fatalf("Error in summary,", err)
	}
	if sum3.Status != "ok" {
		t.Fatalf("Error in summary, ", sum.Status)
	}
	if len(sum3.All) != 2 {
		t.Fatalf("Error in summary, ", sum.All)
	}

	keycache.FlushCache()

	os.Remove("/tmp/db1.json")
}
