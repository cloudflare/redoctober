// Tests the Red October API. These tests ensure consistency in the API's
// return status codes and data. They do not explicitly test for correctness
// of the functions called (that is handled by the tests in /core). Running
// these tests first require that you build this project and have a recent
// binary of it in either the /redoctober folder or in $GOPATH/bin/redoctober.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/core"
)

const baseURL = "https://localhost:8080/"

var (
	// Inputs that are used in multiple test cases are put here to reduce verbosity.
	createVaultInput = &core.CreateRequest{Name: "Alice", Password: "Lewis"}

	createUserInput1 = &core.CreateUserRequest{Name: "Bill", Password: "Lizard"}
	createUserInput2 = &core.CreateUserRequest{Name: "Cat", Password: "Cheshire"}
	createUserInput3 = &core.CreateUserRequest{Name: "Dodo", Password: "Dodgson"}

	delegateInput1 = &core.DelegateRequest{
		Name: createUserInput1.Name,
		Password: createUserInput1.Password,
		Time: "2h34m",
		Uses: 1,
	}
	delegateInput2 = &core.DelegateRequest{
		Name: createUserInput2.Name,
		Password: createUserInput2.Password,
		Time: "2h34m",
		Uses: 1,
	}

	encryptInput     = &core.EncryptRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		Owners:   []string{createUserInput1.Name, createUserInput2.Name},
		Data:     []byte("V2h5IGlzIGEgcmF2ZW4gbGlrZSBhIHdyaXRpbmcgZGVzaz8K"),
	}
)

func init() {
	// Because the certificate being used is self-signed, InsecureSkipVerify must be enabled
	// to avoid the POST requests from failing.
	cfg := &tls.Config{
		InsecureSkipVerify: true,
	}

	http.DefaultClient.Transport = &http.Transport{
		TLSClientConfig: cfg,
	}
}

func setup(t *testing.T) (cmd *exec.Cmd) {
	// Look for the redoctober binary in current directory and then in $GOPATH/bin
	binaryPath, err := exec.LookPath("./redoctober")
	if err != nil {
		goPathBinary := fmt.Sprintf("%s/bin/redoctober", os.Getenv("GOPATH"))
		binaryPath, err = exec.LookPath(goPathBinary)
		if err != nil {
			t.Fatalf(`Could not find redoctober binary at "./redoctober" or "%s"`, goPathBinary)
		}
	}

	cmd = exec.Command(binaryPath, "-addr=localhost:8080", "-certs=testdata/server.crt",
		"-keys=testdata/server.pem", "-vaultpath=memory")

	if err := cmd.Start(); err != nil {
		t.Fatalf("Error running redoctober command, %v", err)
	}

	// Give the server time to start up.
	time.Sleep(500 * time.Millisecond)

	return
}

func teardown(t *testing.T, cmd *exec.Cmd) {
	err := cmd.Process.Kill()
	if err != nil {
		t.Fatalf("Error killing the redoctober server, %v", err)
	}
}

func post(api string, v interface{}) (respBytes []byte, response *http.Response, err error) {
	jsonBytes, err := json.Marshal(v)
	if err != nil {
		return
	}

	buffer := bytes.NewBuffer(jsonBytes)
	response, err = http.Post(baseURL+api, "text/json", buffer)
	if err != nil {
		return
	}

	respBytes, err = ioutil.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		return
	}

	return
}

// postAndTest executes a POST request and then tests to see if the HTTP status code matches a given
// values and that the "Status" field in the body of the response matches a given value. If either
// of these checks fails an error is returned.
func postAndTest(api string, v interface{}, expectedStatusCode int, expectedStatus string) error {
	respBytes, response, err := post(api, v)
	if err != nil {
		return err
	}

	if response.StatusCode != expectedStatusCode {
		errorString := fmt.Sprintf("Expected StatusCode %d, got %d instead", expectedStatusCode, response.StatusCode)
		return errors.New(errorString)
	}

	var s core.ResponseData
	if err = json.Unmarshal(respBytes, &s); err != nil {
		return err
	}

	if s.Status != expectedStatus {
		errorString := fmt.Sprintf("Expected Status \"%s\", got \"%s\" instead", expectedStatus, s.Status)
		return errors.New(errorString)
	}

	return nil
}

// Test that the /create API endpoint works and returns data in the correct format.
func TestCreate(t *testing.T) {
	cmd := setup(t)

	createVaultInput2 := &core.CreateRequest{Name: "Bill", Password: "Lizard"}

	// Check that creating the initial vault returns {Status: "ok"}
	err := postAndTest("create", createVaultInput, 200, "ok")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}

	// Check that trying to create another vault returns {Status: "Vault is already created"}
	err = postAndTest("create", createVaultInput2, 200, "Vault is already created")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating second vault, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /delegate API endpoint works and returns data in the correct format.
func TestDelegate(t *testing.T) {
	cmd := setup(t)

	// Check that delegating before a vault is creating returns {Status: "Vault is not created yet"}
	err := postAndTest("delegate", delegateInput1, 200, "Vault is not created yet")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that delegating after creating a vault returns {Status: "ok"}
	if _, _, err = post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}

	err = postAndTest("delegate", delegateInput1, 200, "ok")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /create-user API endpoint works and returns data in the correct format.
func TestCreateUser(t *testing.T) {
	cmd := setup(t)

	// Check that creating a user before a vault is creating returns {Status: "Vault is not created yet"}
	err := postAndTest("create-user", createUserInput1, 200, "Vault is not created yet")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that creating a user after creating a vault returns {Status: "ok"}
	if _, _, err = post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	err = postAndTest("create-user", createUserInput1, 200, "ok")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that creating a duplicate user returns {Status: "User with that name already exists"}
	err = postAndTest("create-user", createUserInput1, 200, "User with that name already exists")
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error sending POST request, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /modify API endpoint works and returns data in the correct format.
func TestModify(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user, %v", err)
	}

	// Check revoking the admin status of a non-admin user.
	modifyInput := &core.ModifyRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		ToModify: createUserInput1.Name,
		Command:  "revoke",
	}
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error revoking admin status of non-admin user, %v", err)
	}

	// Check granting admin status to a non-admin user.
	modifyInput.Command = "admin"
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error granting admin status to non-admin user, %v", err)
	}

	// Check revoking admin status of an admin user.
	modifyInput.Command = "revoke"
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error revoke admin status of admin user, %v", err)
	}

	// Check granting admin status with wrong password.
	modifyInput.Command = "grant"
	modifyInput.Password = "wrongpassword"
	if err := postAndTest("modify", modifyInput, 200, "Wrong Password"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error granting admin status with wrong password, %v", err)
	}

	// Check revoking admin status with the issuing user not being an admin.
	modifyInput.Command = "revoke"
	modifyInput.ToModify = createVaultInput.Name
	modifyInput.Name = createUserInput1.Name
	modifyInput.Password = createUserInput1.Password
	if err := postAndTest("modify", modifyInput, 200, "Admin required"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error revoking admin status by a non-admin user, %v", err)
	}

	// Check deleting a user.
	modifyInput.Command = "delete"
	modifyInput.ToModify = createUserInput1.Name
	modifyInput.Name = createVaultInput.Name
	modifyInput.Password = createVaultInput.Password
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error deleting user, %v", err)
	}

	// Check granting admin status to a non-existent user
	modifyInput.Command = "grant"
	if err := postAndTest("modify", modifyInput, 200, "core: record to modify missing"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error granting admin status to a non-existent user, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /encrypt API endpoint works and returns data in the correct format.
func TestEncrypt(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 2, %v", err)
	}

	// Use a copy of encryptInput because we will be modifying the struct.
	encryptInput2 := *encryptInput

	// Check encrypting data.
	if err := postAndTest("encrypt", encryptInput2, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data, %v", err)
	}

	// Check encrypting data with invalid user.
	encryptInput2.Name = "wronguser"
	if err := postAndTest("encrypt", encryptInput2, 200, "User not present"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data with invalid user, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /decrypt API endpoint works and returns data in the correct format.
func TestDecrypt(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 2, %v", err)
	}
	if _, _, err := post("create-user", createUserInput3); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 3, %v", err)
	}

	// Encrypt data and keep the encrypted response.
	respBytes, _, err := post("encrypt", encryptInput)

	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data, %v", err)
	}
	var s core.ResponseData
	if err := json.Unmarshal(respBytes, &s); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data, %v", err)
	}
	encryptedData := s.Response

	decryptInput := &core.DecryptRequest{
		Name: "Alice",
		Password: "Lewis",
		Data: encryptedData,
	}

	// Check the first decrypt command (where not enough owners have decrypted yet).
	if err := postAndTest("decrypt", decryptInput, 200, "Need more delegated keys"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error decrypting data, %v", err)
	}

	// Check decrypting when 2 users have delegated.
	if _, _, err := post("delegate", delegateInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error delegating with user 1, %v", err)
	}
	if _, _, err := post("delegate", delegateInput2); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error delegating with user 2, %v", err)
	}
	if err := postAndTest("decrypt", decryptInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error decrypting data, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /owners API endpoint works and returns data in the correct format.
func TestOwners(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 2, %v", err)
	}
	if _, _, err := post("create-user", createUserInput3); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 3, %v", err)
	}

	respBytes, _, err := post("encrypt", encryptInput)

	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data, %v", err)
	}
	var s core.ResponseData
	if err := json.Unmarshal(respBytes, &s); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error encrypting data, %v", err)
	}

	// Check getting the owners of the encrypted data.
	ownersInput := &core.OwnersRequest{Data: s.Response}

	respBytes, response, err := post("owners", ownersInput)
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting owners, %v", err)
	}

	if response.StatusCode != 200 {
		teardown(t, cmd)
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	var ownersData core.OwnersData
	if err = json.Unmarshal(respBytes, &ownersData); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting owners, %v", err)
	}

	if ownersData.Status != "ok" {
		teardown(t, cmd)
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", ownersData.Status)
	}
	if len(ownersData.Owners) != 2 {
		teardown(t, cmd)
		t.Fatalf("Expected there to be 2 owners, got %d instead", len(ownersData.Owners))
	}

	teardown(t, cmd)
}

// Test that the /summary API endpoint works and returns data in the correct format.
func TestSummary(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check that summary works when no users have delegated.
	summaryInput := &core.SummaryRequest{Name: createVaultInput.Name, Password: createVaultInput.Password}

	respBytes, response, err := post("summary", summaryInput)
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting summary, %v", err)
	}

	if response.StatusCode != 200 {
		teardown(t, cmd)
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	var summaryData core.SummaryData
	if err = json.Unmarshal(respBytes, &summaryData); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting owners, %v", err)
	}

	if summaryData.Status != "ok" {
		teardown(t, cmd)
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", summaryData.Status)
	}

	// Check that there are exactly 2 listings in All.
	if len(summaryData.All) != 2 {
		teardown(t, cmd)
		t.Fatalf("Expected there to be 2 listings in All, got %d instead", len(summaryData.All))
	}

	// Check user 1's listing.
	data, ok := summaryData.All[createUserInput1.Name]
	if !ok {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createUserInput1.Name)
	}
	if data.Admin {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to not be an admin", createUserInput1.Name)
	}
	if data.Type != "RSA" {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to have type \"RSA\"", createUserInput1.Name)
	}

	// Check the admin user's listing.
	data, ok = summaryData.All[createVaultInput.Name]
	if !ok {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createVaultInput.Name)
	}
	if !data.Admin {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to be an admin", createVaultInput.Name)
	}
	if data.Type != "RSA" {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to have type \"RSA\"", createVaultInput.Name)
	}

	// Check that there are no live users.
	if len(summaryData.Live) != 0 {
		teardown(t, cmd)
		t.Fatalf("Expected there to be 0 lives users, got %d instead", len(summaryData.Live))
	}

	// Delegate user 1 and check summary's response.
	if _, _, err := post("delegate", delegateInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error delegating user 1, %v", err)
	}

	respBytes, response, err = post("summary", summaryInput)
	if err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting summary, %v", err)
	}

	if response.StatusCode != 200 {
		teardown(t, cmd)
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	if err = json.Unmarshal(respBytes, &summaryData); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error getting owners, %v", err)
	}

	if summaryData.Status != "ok" {
		teardown(t, cmd)
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", summaryData.Status)
	}

	// Check that there is exacly one listing in Live
	if len(summaryData.Live) != 1 {
		teardown(t, cmd)
		t.Fatalf("Expected there to be 2 listings in Live, got %d instead", len(summaryData.Live))
	}

	// Check user 1's listing in Live
	_, ok = summaryData.Live[createUserInput1.Name]
	if !ok {
		teardown(t, cmd)
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createUserInput1.Name)
	}

	teardown(t, cmd)
}

// Test that the /password API endpoint works and returns data in the correct format.
func TestPassword(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check changing password with invalid password.
	passwordInput := &core.PasswordRequest{
		Name: createUserInput1.Name,
		Password: "badpassword",
		NewPassword: "worsepassword",
	}
	if err := postAndTest("password", passwordInput, 200, "Wrong Password"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error changing password with invalid passsowrd, %v", err)
	}

	// Check changing password with nonexistent user.
	passwordInput = &core.PasswordRequest{
		Name: createUserInput2.Name,
		Password: "badpassword",
		NewPassword: "worsepassword",
	}
	if err := postAndTest("password", passwordInput, 200, "Record not present"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error changing password with nonexistent user, %v", err)
	}

	// Check changing the password properly.
	passwordInput = &core.PasswordRequest{
		Name: createUserInput1.Name,
		Password: createUserInput1.Password,
		NewPassword: "foobar",
	}
	if err := postAndTest("password", passwordInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error changing password, %v", err)
	}

	teardown(t, cmd)
}

// Test that the /purge API endpoint works and returns data in the correct format.
func TestPurge(t *testing.T) {
	cmd := setup(t)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check purging with non-admin user
	purgeInput := &core.PurgeRequest{
		Name: createUserInput1.Name,
		Password: createUserInput1.Password,
	}
	if err := postAndTest("purge", purgeInput, 200, "Admin required"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error purging with non-admin user, %v", err)
	}

	// Check purging with admin user
	purgeInput = &core.PurgeRequest{
		Name: createVaultInput.Name,
		Password: createVaultInput.Password,
	}
	if err := postAndTest("purge", purgeInput, 200, "ok"); err != nil {
		teardown(t, cmd)
		t.Fatalf("Error purging with admin user, %v", err)
	}

	teardown(t, cmd)
}
