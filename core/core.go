// Package core handles the main operations of the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/cloudflare/redoctober/cryptor"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
	"log"
)

// Each of these structures corresponds to the JSON expected on the
// correspondingly named URI (e.g. the delegate structure maps to the
// JSON that should be sent on the /delegate URI and it is handled by
// the Delegate function below).

type create struct {
	Name     string
	Password string
}

type summary struct {
	Name     string
	Password string
}

type delegate struct {
	Name     string
	Password string

	Uses int
	Time string
}

type password struct {
	Name     string
	Password string

	NewPassword string
}

type encrypt struct {
	Name     string
	Password string

	Minimum int
	Owners  []string
	Data    []byte
}

type decrypt struct {
	Name     string
	Password string

	Data []byte
}

type modify struct {
	Name     string
	Password string

	ToModify string
	Command  string
}

// These structures map the JSON responses that will be sent from the API

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

// Helper functions that create JSON responses sent by core

func jsonStatusOk() ([]byte, error) {
	return json.Marshal(status{Status: "ok"})
}
func jsonStatusError(err error) ([]byte, error) {
	return json.Marshal(status{Status: err.Error()})
}
func jsonSummary() ([]byte, error) {
	return json.Marshal(summaryData{Status: "ok", Live: keycache.GetSummary(), All: passvault.GetSummary()})
}
func jsonResponse(resp []byte) ([]byte, error) {
	return json.Marshal(responseData{Status: "ok", Response: resp})
}

// validateAdmin checks that the username and password passed in are
// correct and that the user is an admin
func validateAdmin(name, password string) error {
	if passvault.NumRecords() == 0 {
		return errors.New("Vault is not created yet")
	}

	pr, ok := passvault.GetRecord(name)
	if !ok {
		return errors.New("User not present")
	}
	if err := pr.ValidatePassword(password); err != nil {
		return err
	}
	if !pr.IsAdmin() {
		return errors.New("Admin required")
	}

	return nil
}

// Init reads the records from disk from a given path
func Init(path string) (err error) {
	if err = passvault.InitFromDisk(path); err != nil {
		err = fmt.Errorf("Failed to load password vault %s: %s", path, err)
	}
	return
}

// Create processes a create request.
func Create(jsonIn []byte) ([]byte, error) {
	var s create
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if passvault.NumRecords() != 0 {
		return jsonStatusError(errors.New("Vault is already created"))
	}

	if _, err := passvault.AddNewRecord(s.Name, s.Password, true); err != nil {
		log.Printf("Error adding record for %s: %s\n", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Summary processes a summary request.
func Summary(jsonIn []byte) ([]byte, error) {
	var s summary
	keycache.Refresh()

	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if passvault.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	if err := validateAdmin(s.Name, s.Password); err != nil {
		log.Printf("Error validating admin status of %s: %s", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonSummary()
}

// Delegate processes a delegation request.
func Delegate(jsonIn []byte) ([]byte, error) {
	var s delegate
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if passvault.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	// Find password record for user and verify that their password
	// matches. If not found then add a new entry for this user.

	pr, found := passvault.GetRecord(s.Name)
	if found {
		if err := pr.ValidatePassword(s.Password); err != nil {
			return jsonStatusError(err)
		}
	} else {
		var err error
		if pr, err = passvault.AddNewRecord(s.Name, s.Password, false); err != nil {
			log.Printf("Error adding record for %s: %s\n", s.Name, err)
			return jsonStatusError(err)
		}
	}

	// add signed-in record to active set
	if err := keycache.AddKeyFromRecord(pr, s.Name, s.Password, s.Uses, s.Time); err != nil {
		log.Printf("Error adding key to cache for %s: %s\n", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Password processes a password change request.
func Password(jsonIn []byte) ([]byte, error) {
	var s password
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if passvault.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	// add signed-in record to active set
	if err := passvault.ChangePassword(s.Name, s.Password, s.NewPassword); err != nil {
		log.Println("Error changing password:", err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Encrypt processes an encrypt request.
func Encrypt(jsonIn []byte) ([]byte, error) {
	var s encrypt
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if err := validateAdmin(s.Name, s.Password); err != nil {
		log.Println("Error validating admin status", err)
		return jsonStatusError(err)
	}

	// Encrypt file with list of owners
	if resp, err := cryptor.Encrypt(s.Data, s.Owners, s.Minimum); err != nil {
		log.Println("Error encrypting:", err)
		return jsonStatusError(err)
	} else {
		return jsonResponse(resp)
	}
}

// Decrypt processes a decrypt request.
func Decrypt(jsonIn []byte) ([]byte, error) {
	var s decrypt
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	err = validateAdmin(s.Name, s.Password)
	if err != nil {
		log.Println("Error validating admin status", err)
		return jsonStatusError(err)
	}

	resp, err := cryptor.Decrypt(s.Data)
	if err != nil {
		log.Println("Error decrypting:", err)
		return jsonStatusError(err)
	}

	return jsonResponse(resp)
}

// Modify processes a modify request.
func Modify(jsonIn []byte) ([]byte, error) {
	var s modify

	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if err := validateAdmin(s.Name, s.Password); err != nil {
		log.Printf("Error validating admin status of %s: %s", s.Name, err)
		return jsonStatusError(err)
	}

	if _, ok := passvault.GetRecord(s.ToModify); !ok {
		return jsonStatusError(errors.New("Record to modify missing"))
	}

	if s.Name == s.ToModify {
		return jsonStatusError(errors.New("Cannot modify own record"))
	}

	var err error
	switch s.Command {
	case "delete":
		err = passvault.DeleteRecord(s.ToModify)
	case "revoke":
		err = passvault.RevokeRecord(s.ToModify)
	case "admin":
		err = passvault.MakeAdmin(s.ToModify)
	default:
		return jsonStatusError(errors.New("Unknown command"))
	}

	if err != nil {
		return jsonStatusError(err)
	} else {
		return jsonStatusOk()
	}
}
