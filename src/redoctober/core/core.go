// Package core handles the main operations of the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"errors"
	"log"
	"redoctober/cryptor"
	"redoctober/keycache"
	"redoctober/passvault"
)

type credential struct {
	Name     string
	Password string
}

// format of incoming sign-in request
type create struct {
	credential
}

type summary struct {
	credential
}

type delegate struct {
	credential
	Uses     int
	Time     string
}

type password struct {
	credential
	NewPassword string
}

type encrypt struct {
	credential
	Minimum  int
	Owners   []string
	Data     []byte
}

type decrypt struct {
	credential
	Data     []byte
}

type modify struct {
	credential
	ToModify string
	Command  string
}

// response JSON format
type status struct {
	Status string
}

type responseData struct {
	Status   string
	Response []byte
}

type summaryData struct {
	Status string
	Live   map[string]keycache.ActiveUser
	All    map[string]passvault.Summary
}

func errToJson(err error) (ret []byte) {
	if err == nil {
		ret, _ = json.Marshal(status{Status: "ok"})
	} else {
		ret, _ = json.Marshal(status{Status: err.Error()})
	}
	return
}

func summaryToJson(err error) (ret []byte) {
	if err == nil {
		ret, _ = json.Marshal(summaryData{Status: "ok", Live: keycache.GetSummary(), All: passvault.GetSummary()})
	} else {
		ret, _ = json.Marshal(status{Status: err.Error()})
	}
	return
}

func responseToJson(resp []byte, err error) (ret []byte) {
	if err == nil {
		ret, _ = json.Marshal(responseData{Status: "ok", Response: resp})
	} else {
		ret, _ = json.Marshal(status{Status: err.Error()})
	}
	return
}

func validateAdmin(name string, password string) (err error) {
	if passvault.NumRecords() == 0 {
		return errors.New("Vault is not created yet")
	}

	// find record
	passwordRec, ok := passvault.GetRecord(name)
	if !ok {
		return errors.New("User not present")
	}
	err = passwordRec.ValidatePassword(password)
	if err != nil {
		return
	}
	if !passwordRec.IsAdmin() {
		return errors.New("Admin required")
	}

	return
}

// Init reads the records from disk from a given path.
func Init(path string) {
	passvault.InitFromDisk(path)
}

// Create processes a create request.
func Create(jsonIn []byte) []byte {
	var s create
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	if passvault.NumRecords() != 0 {
		return errToJson(errors.New("Vault is already created"))
	}

	_, err = passvault.AddNewRecord(s.Name, s.Password, true)
	if err != nil {
		log.Println("Error adding record:", err)
		return errToJson(err)
	}

	return errToJson(err)
}

// Summary processes a summary request.
func Summary(jsonIn []byte) []byte {
	var s summary
	keycache.Refresh()

	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	if passvault.NumRecords() == 0 {
		return errToJson(errors.New("Vault is not created yet"))
	}

	// validate admin
	err = validateAdmin(s.Name, s.Password)
	if err != nil {
		log.Println("Error validating admin status", err)
		return errToJson(err)
	}

	// populate
	return summaryToJson(err)
}

// Delegate processes a delegation request.
func Delegate(jsonIn []byte) []byte {
	var s delegate
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	if passvault.NumRecords() == 0 {
		return errToJson(errors.New("Vault is not created yet"))
	}

	// find record
	passwordRec, ok := passvault.GetRecord(s.Name)
	if ok {
		err = passwordRec.ValidatePassword(s.Password)
		if err != nil {
			return errToJson(err)
		}
	} else {
		passwordRec, err = passvault.AddNewRecord(s.Name, s.Password, false)
		if err != nil {
			log.Println("Error adding record:", err)
			return errToJson(err)
		}
	}

	// add signed-in record to active set
	err = keycache.AddKeyFromRecord(passwordRec, s.Name, s.Password, s.Uses, s.Time)
	if err != nil {
		log.Println("Error adding key to cache:", err)
		return errToJson(err)
	}

	return errToJson(err)
}

// Password processes a password change request.
func Password(jsonIn []byte) []byte {
	var s password
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	if passvault.NumRecords() == 0 {
		return errToJson(errors.New("Vault is not created yet"))
	}

	// add signed-in record to active set
	err = passvault.ChangePassword(s.Name, s.Password, s.NewPassword)
	if err != nil {
		log.Println("Error changing password:", err)
		return errToJson(err)
	}

	return errToJson(err)
}

// Encrypt processes an encrypt request.
func Encrypt(jsonIn []byte) (ret []byte) {
	var s encrypt
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	err = validateAdmin(s.Name, s.Password)
	if err != nil {
		log.Println("Error validating admin status", err)
		return errToJson(err)
	}

	// Encrypt file with list of owners
	resp, err := cryptor.Encrypt(s.Data, s.Owners, s.Minimum)
	if err != nil {
		log.Println("Error encrypting:", err)
		return errToJson(err)
	}

	return responseToJson(resp, err)
}

// Decrypt processes a decrypt request.
func Decrypt(jsonIn []byte) (ret []byte) {
	var s decrypt
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	err = validateAdmin(s.Name, s.Password)
	if err != nil {
		log.Println("Error validating admin status", err)
		return errToJson(err)
	}

	resp, err := cryptor.Decrypt(s.Data)
	if err != nil {
		log.Println("Error decrypting:", err)
		return errToJson(err)
	}

	return responseToJson(resp, err)
}

// Modify processes a modify request.
func Modify(jsonIn []byte) []byte {
	var s modify

	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return errToJson(err)
	}

	err = validateAdmin(s.Name, s.Password)
	if err != nil {
		log.Println("Error validating admin status", err)
		return errToJson(err)
	}

	if _, ok := passvault.GetRecord(s.ToModify); !ok {
		return errToJson(errors.New("Record to modify missing"))
	}

	if s.Name == s.ToModify {
		return errToJson(errors.New("Cannot modify own record"))
	}
	switch s.Command {
	case "delete":
		{
			err = passvault.DeleteRecord(s.ToModify)
		}
	case "revoke":
		{
			err = passvault.RevokeRecord(s.ToModify)
		}
	case "admin":
		{
			err = passvault.MakeAdmin(s.ToModify)
		}
	default:
		{
			return errToJson(errors.New("Unknown command"))
		}
	}
	return errToJson(err)
}
