// Package core handles the main operations of the Red October server.
//
// Copyright (c) 2013 CloudFlare, Inc.

package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/cloudflare/redoctober/cryptor"
	"github.com/cloudflare/redoctober/keycache"
	"github.com/cloudflare/redoctober/passvault"
)

var (
	crypt   cryptor.Cryptor
	records passvault.Records
	cache   keycache.Cache
)

// Each of these structures corresponds to the JSON expected on the
// correspondingly named URI (e.g. the delegate structure maps to the
// JSON that should be sent on the /delegate URI and it is handled by
// the Delegate function below).

type CreateRequest struct {
	Name     string
	Password string
}

type SummaryRequest struct {
	Name     string
	Password string
}

type DelegateRequest struct {
	Name     string
	Password string

	Uses   int
	Time   string
	Users  []string
	Labels []string
}

type PasswordRequest struct {
	Name     string
	Password string

	NewPassword string
}

type EncryptRequest struct {
	Name     string
	Password string

	Owners      []string
	LeftOwners  []string
	RightOwners []string

	Data []byte

	Labels []string
}

type DecryptRequest struct {
	Name     string
	Password string

	Data []byte
}

type OwnersRequest struct {
	Data []byte
}

type ModifyRequest struct {
	Name     string
	Password string

	ToModify string
	Command  string
}

// These structures map the JSON responses that will be sent from the API

type ResponseData struct {
	Status   string
	Response []byte `json:",omitempty"`
}

type SummaryData struct {
	Status string
	Live   map[string]keycache.ActiveUser
	All    map[string]passvault.Summary
}

type DecryptWithDelegates struct {
	Data      []byte
	Secure    bool
	Delegates []string
}

type OwnersData struct {
	Status string
	Owners []string
}

// Helper functions that create JSON responses sent by core

func jsonStatusOk() ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok"})
}
func jsonStatusError(err error) ([]byte, error) {
	return json.Marshal(ResponseData{Status: err.Error()})
}
func jsonSummary() ([]byte, error) {
	return json.Marshal(SummaryData{Status: "ok", Live: cache.GetSummary(), All: records.GetSummary()})
}
func jsonResponse(resp []byte) ([]byte, error) {
	return json.Marshal(ResponseData{Status: "ok", Response: resp})
}

// validateUser checks that the username and password passed in are
// correct. If admin is true, the user must be an admin as well.
func validateUser(name, password string, admin bool) error {
	if records.NumRecords() == 0 {
		return errors.New("Vault is not created yet")
	}

	pr, ok := records.GetRecord(name)
	if !ok {
		return errors.New("User not present")
	}

	if err := pr.ValidatePassword(password); err != nil {
		return err
	}

	if admin && !pr.IsAdmin() {
		return errors.New("Admin required")
	}

	return nil
}

// validateName checks that the username and password pass the minimal
// validation check
func validateName(name, password string) error {
	if name == "" {
		return errors.New("User name must not be blank")
	}
	if password == "" {
		return errors.New("Password must be at least one character")
	}

	return nil
}

// Init reads the records from disk from a given path
func Init(path string) (err error) {
	if records, err = passvault.InitFrom(path); err != nil {
		err = fmt.Errorf("Failed to load password vault %s: %s", path, err)
	}

	cache = keycache.Cache{UserKeys: make(map[string]keycache.ActiveUser)}
	crypt = cryptor.New(&records, &cache)

	return
}

// Create processes a create request.
func Create(jsonIn []byte) ([]byte, error) {
	var s CreateRequest
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() != 0 {
		return jsonStatusError(errors.New("Vault is already created"))
	}

	// Validate the Name and Password as valid
	if err := validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	if _, err := records.AddNewRecord(s.Name, s.Password, true, passvault.DefaultRecordType); err != nil {
		log.Printf("Error adding record for %s: %s\n", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Summary processes a summary request.
func Summary(jsonIn []byte) ([]byte, error) {
	var s SummaryRequest
	cache.Refresh()

	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	if err := validateUser(s.Name, s.Password, false); err != nil {
		log.Printf("failed to validate %s in summary request: %s", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonSummary()
}

// Delegate processes a delegation request.
func Delegate(jsonIn []byte) ([]byte, error) {
	var s DelegateRequest
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	// Validate the Name and Password as valid
	if err := validateName(s.Name, s.Password); err != nil {
		return jsonStatusError(err)
	}

	// Find password record for user and verify that their password
	// matches. If not found then add a new entry for this user.

	pr, found := records.GetRecord(s.Name)
	if found {
		if err := pr.ValidatePassword(s.Password); err != nil {
			return jsonStatusError(err)
		}
	} else {
		var err error
		if pr, err = records.AddNewRecord(s.Name, s.Password, false, passvault.DefaultRecordType); err != nil {
			log.Printf("Error adding record for %s: %s\n", s.Name, err)
			return jsonStatusError(err)
		}
	}

	// add signed-in record to active set
	if err := cache.AddKeyFromRecord(pr, s.Name, s.Password, s.Users, s.Labels, s.Uses, s.Time); err != nil {
		log.Printf("Error adding key to cache for %s: %s\n", s.Name, err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Password processes a password change request.
func Password(jsonIn []byte) ([]byte, error) {
	var s PasswordRequest
	if err := json.Unmarshal(jsonIn, &s); err != nil {
		return jsonStatusError(err)
	}

	if records.NumRecords() == 0 {
		return jsonStatusError(errors.New("Vault is not created yet"))
	}

	// add signed-in record to active set
	if err := records.ChangePassword(s.Name, s.Password, s.NewPassword); err != nil {
		log.Println("Error changing password:", err)
		return jsonStatusError(err)
	}

	return jsonStatusOk()
}

// Encrypt processes an encrypt request.
func Encrypt(jsonIn []byte) ([]byte, error) {
	var s EncryptRequest

	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	defer func() {
		if err != nil {
			log.Printf("encrypt: request for encryption from %s failed: %v", s.Name, err)
		} else {
			log.Printf("encrypt: successful encryption for %s", s.Name)
		}
	}()

	if err = validateUser(s.Name, s.Password, false); err != nil {
		return jsonStatusError(err)
	}

	access := cryptor.AccessStructure{
		Names:      s.Owners,
		LeftNames:  s.LeftOwners,
		RightNames: s.RightOwners,
	}

	resp, err := crypt.Encrypt(s.Data, s.Labels, access)
	if err != nil {
		return jsonStatusError(err)
	} else {
		return jsonResponse(resp)
	}
}

// Decrypt processes a decrypt request.
func Decrypt(jsonIn []byte) ([]byte, error) {
	var s DecryptRequest
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		log.Printf("decrypt: failed to unmarshal input: %v", err)
		return jsonStatusError(err)
	}

	defer func() {
		if err != nil {
			log.Printf("decrypt: request for decryption from %s failed: %v", s.Name, err)
		} else {
			log.Printf("decrypt: successful decryption for %s", s.Name)
		}
	}()

	err = validateUser(s.Name, s.Password, false)
	if err != nil {
		return jsonStatusError(err)
	}

	data, names, secure, err := crypt.Decrypt(s.Data, s.Name)
	if err != nil {
		return jsonStatusError(err)
	}

	resp := &DecryptWithDelegates{
		Data:      data,
		Secure:    secure,
		Delegates: names,
	}

	out, err := json.Marshal(resp)
	if err != nil {
		return jsonStatusError(err)
	}

	return jsonResponse(out)
}

// Modify processes a modify request.
func Modify(jsonIn []byte) ([]byte, error) {
	var s ModifyRequest

	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		return jsonStatusError(err)
	}

	defer func() {
		if err != nil {
			log.Printf("modify: attempt to modify %s by %s fail: %v", s.ToModify, s.Name, err)
		} else {
			log.Printf("modify: attempt to modify %s by %s succeeded", s.ToModify, s.Name)
		}
	}()

	if err = validateUser(s.Name, s.Password, true); err != nil {
		return jsonStatusError(err)
	}

	if _, ok := records.GetRecord(s.ToModify); !ok {
		err = errors.New("core: record to modify missing")
		return jsonStatusError(err)
	}

	if s.Name == s.ToModify {
		err = errors.New("core: cannot modify own record")
		return jsonStatusError(err)
	}

	switch s.Command {
	case "delete":
		err = records.DeleteRecord(s.ToModify)
	case "revoke":
		err = records.RevokeRecord(s.ToModify)
	case "admin":
		err = records.MakeAdmin(s.ToModify)
	default:
		err = fmt.Errorf("core: unknown command '%s' passed to modify", s.Command)
		return jsonStatusError(err)
	}

	if err != nil {
		return jsonStatusError(err)
	} else {
		return jsonStatusOk()
	}
}

// Owners processes a owners request.
func Owners(jsonIn []byte) ([]byte, error) {
	var s OwnersRequest
	err := json.Unmarshal(jsonIn, &s)
	if err != nil {
		log.Println("Error unmarshaling input:", err)
		return jsonStatusError(err)
	}

	names, err := crypt.GetOwners(s.Data)
	if err != nil {
		log.Println("Error listing owners:", err)
		return jsonStatusError(err)
	}

	return json.Marshal(OwnersData{Status: "ok", Owners: names})
}
