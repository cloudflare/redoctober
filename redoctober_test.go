// Tests the Red October API. These tests ensure consistency in the API's
// return status codes and data. They do not explicitly test for correctness
// of the functions called (that is handled by the tests in /core). Running
// these tests first require that you build this project and have a recent
// binary of it in either the /redoctober folder or in $GOPATH/bin/redoctober.

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/config"
	"github.com/cloudflare/redoctober/core"
	"github.com/cloudflare/redoctober/persist"
)

const baseURL = "https://localhost:8080/"

var (
	// Inputs that are used in multiple test cases are put here to reduce verbosity.
	createVaultInput = &core.CreateRequest{Name: "Alice", Password: "Lewis"}

	createUserInput1 = &core.CreateUserRequest{Name: "Bill", Password: "Lizard"}
	createUserInput2 = &core.CreateUserRequest{Name: "Cat", Password: "Cheshire"}
	createUserInput3 = &core.CreateUserRequest{Name: "Dodo", Password: "Dodgson"}

	delegateInput1 = &core.DelegateRequest{
		Name:     createUserInput1.Name,
		Password: createUserInput1.Password,
		Time:     "2h34m",
		Uses:     1,
	}
	delegateInput2 = &core.DelegateRequest{
		Name:     createUserInput2.Name,
		Password: createUserInput2.Password,
		Time:     "2h34m",
		Uses:     1,
	}
	delegateInput3 = &core.DelegateRequest{
		Name:     createUserInput3.Name,
		Password: createUserInput3.Password,
		Time:     "2h34m",
		Uses:     1,
	}
	delegateInput4 = &core.DelegateRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		Time:     "2h34m",
		Uses:     1,
	}

	encryptMessage = "Why is a raven like a writing desk?\n"
	encryptInput   = &core.EncryptRequest{
		Minimum:  2,
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
	const maxAttempts = 5

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

	attempts := 0

	for {
		resp, err := http.Get("http://localhost:8081")
		if err == nil {
			resp.Body.Close()
			break
		}

		attempts++
		if attempts > maxAttempts {
			t.Fatalf("failed to start redoctober (max connection attempts exceeded)")
		}
		time.Sleep(500 * time.Millisecond)
	}

	return
}

func teardown(t *testing.T, cmd *exec.Cmd) {
	err := cmd.Process.Kill()
	if err != nil {
		t.Fatalf("Error killing the redoctober server, %v", err)
	}
	time.Sleep(250 * time.Millisecond)
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
	defer teardown(t, cmd)

	createVaultInput2 := &core.CreateRequest{Name: "Bill", Password: "Lizard"}

	// Check that creating the initial vault returns {Status: "ok"}
	err := postAndTest("create", createVaultInput, 200, "ok")
	if err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}

	// Check that trying to create another vault returns {Status: "Vault is already created"}
	err = postAndTest("create", createVaultInput2, 200, "Vault is already created")
	if err != nil {
		t.Fatalf("Error creating second vault, %v", err)
	}
}

// Test that the /delegate API endpoint works and returns data in the correct format.
func TestDelegate(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Check that delegating before a vault is creating returns {Status: "Vault is not created yet"}
	err := postAndTest("delegate", delegateInput1, 200, "Vault is not created yet")
	if err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that delegating after creating a vault returns {Status: "ok"}
	if _, _, err = post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}

	err = postAndTest("delegate", delegateInput1, 200, "ok")
	if err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}
}

// Test that the /create-user API endpoint works and returns data in the correct format.
func TestCreateUser(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Check that creating a user before a vault is creating returns {Status: "Vault is not created yet"}
	err := postAndTest("create-user", createUserInput1, 200, "Vault is not created yet")
	if err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that creating a user after creating a vault returns {Status: "ok"}
	if _, _, err = post("create", createVaultInput); err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}

	err = postAndTest("create-user", createUserInput1, 200, "ok")
	if err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}

	// Check that creating a duplicate user returns {Status: "User with that name already exists"}
	err = postAndTest("create-user", createUserInput1, 200, "User with that name already exists")
	if err != nil {
		t.Fatalf("Error sending POST request, %v", err)
	}
}

// Test that the /modify API endpoint works and returns data in the correct format.
func TestModify(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
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
		t.Fatalf("Error revoking admin status of non-admin user, %v", err)
	}

	// Check granting admin status to a non-admin user.
	modifyInput.Command = "admin"
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		t.Fatalf("Error granting admin status to non-admin user, %v", err)
	}

	// Check revoking admin status of an admin user.
	modifyInput.Command = "revoke"
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		t.Fatalf("Error revoke admin status of admin user, %v", err)
	}

	// Check granting admin status with wrong password.
	modifyInput.Command = "grant"
	modifyInput.Password = "wrongpassword"
	if err := postAndTest("modify", modifyInput, 200, "Wrong Password"); err != nil {
		t.Fatalf("Error granting admin status with wrong password, %v", err)
	}

	// Check revoking admin status with the issuing user not being an admin.
	modifyInput.Command = "revoke"
	modifyInput.ToModify = createVaultInput.Name
	modifyInput.Name = createUserInput1.Name
	modifyInput.Password = createUserInput1.Password
	if err := postAndTest("modify", modifyInput, 200, "Admin required"); err != nil {
		t.Fatalf("Error revoking admin status by a non-admin user, %v", err)
	}

	// Check deleting a user.
	modifyInput.Command = "delete"
	modifyInput.ToModify = createUserInput1.Name
	modifyInput.Name = createVaultInput.Name
	modifyInput.Password = createVaultInput.Password
	if err := postAndTest("modify", modifyInput, 200, "ok"); err != nil {
		t.Fatalf("Error deleting user, %v", err)
	}

	// Check granting admin status to a non-existent user
	modifyInput.Command = "grant"
	if err := postAndTest("modify", modifyInput, 200, "core: record to modify missing"); err != nil {
		t.Fatalf("Error granting admin status to a non-existent user, %v", err)
	}
}

// Test that the /encrypt API endpoint works and returns data in the correct format.
func TestEncrypt(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		t.Fatalf("Error creating user 2, %v", err)
	}

	// Use a copy of encryptInput because we will be modifying the struct.
	encryptInput2 := *encryptInput

	// Check encrypting data.
	if err := postAndTest("encrypt", encryptInput2, 200, "ok"); err != nil {
		t.Fatalf("Error encrypting data, %v", err)
	}

	// Check encrypting data with invalid user.
	encryptInput2.Name = "wronguser"
	if err := postAndTest("encrypt", encryptInput2, 200, "User not present"); err != nil {
		t.Fatalf("Error encrypting data with invalid user, %v", err)
	}
}

// Test that the /decrypt API endpoint works and returns data in the correct format.
func TestDecrypt(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		t.Fatalf("Error creating user 2, %v", err)
	}
	if _, _, err := post("create-user", createUserInput3); err != nil {
		t.Fatalf("Error creating user 3, %v", err)
	}

	// Encrypt data and keep the encrypted response.
	respBytes, _, err := post("encrypt", encryptInput)

	if err != nil {
		t.Fatalf("Error encrypting data, %v", err)
	}
	var s core.ResponseData
	if err := json.Unmarshal(respBytes, &s); err != nil {
		t.Fatalf("Error encrypting data, %v", err)
	}
	encryptedData := s.Response

	decryptInput := &core.DecryptRequest{
		Name:     "Alice",
		Password: "Lewis",
		Data:     encryptedData,
	}

	// Check the first decrypt command (where not enough owners have decrypted yet).
	if err := postAndTest("decrypt", decryptInput, 200, "need more delegated keys"); err != nil {
		t.Fatalf("Error decrypting data, %v", err)
	}

	// Check decrypting when 2 users have delegated.
	if _, _, err := post("delegate", delegateInput1); err != nil {
		t.Fatalf("Error delegating with user 1, %v", err)
	}
	if _, _, err := post("delegate", delegateInput2); err != nil {
		t.Fatalf("Error delegating with user 2, %v", err)
	}
	if err := postAndTest("decrypt", decryptInput, 200, "ok"); err != nil {
		t.Fatalf("Error decrypting data, %v", err)
	}
}

func TestReEncrypt(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		t.Fatalf("Error creating user 2, %v", err)
	}
	if _, _, err := post("create-user", createUserInput3); err != nil {
		t.Fatalf("Error creating user 2, %v", err)
	}

	// Use a copy of encryptInput because we will be modifying the struct.
	encryptInput2 := *encryptInput

	srv, err := client.NewRemoteServer("localhost:8080", "testdata/server.crt")
	if err != nil {
		t.Fatalf("failed to set up client: %s", err)
	}

	resp, err := srv.Encrypt(encryptInput2)
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}

	if resp.Status != "ok" {
		t.Fatalf("failed to encrypt data: %s", resp.Status)
	}

	encryptInput2.Owners = append(encryptInput2.Owners, createUserInput3.Name)
	encryptInput2.Data = resp.Response

	resp, err = srv.Delegate(*delegateInput1)
	if err != nil {
		t.Fatalf("failed to delegate: %s", err)
	} else if resp.Status != "ok" {
		t.Fatalf("failed to delegate: %s", err)
	}

	resp, err = srv.Delegate(*delegateInput2)
	if err != nil {
		t.Fatalf("failed to delegate: %s", err)
	} else if resp.Status != "ok" {
		t.Fatalf("failed to delegate: %s", err)
	}

	resp, err = srv.ReEncrypt(core.ReEncryptRequest(encryptInput2))
	if err != nil {
		t.Fatalf("failed to encrypt data: %s", err)
	}

	if resp.Status != "ok" {
		t.Fatalf("failed to re-encrypt data: %s", resp.Status)
	}
}

// Test that the /owners API endpoint works and returns data in the correct format.
func TestOwners(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}
	if _, _, err := post("create-user", createUserInput2); err != nil {
		t.Fatalf("Error creating user 2, %v", err)
	}
	if _, _, err := post("create-user", createUserInput3); err != nil {
		t.Fatalf("Error creating user 3, %v", err)
	}

	respBytes, _, err := post("encrypt", encryptInput)

	if err != nil {
		t.Fatalf("Error encrypting data, %v", err)
	}
	var s core.ResponseData
	if err := json.Unmarshal(respBytes, &s); err != nil {
		t.Fatalf("Error encrypting data, %v", err)
	}

	// Check getting the owners of the encrypted data.
	ownersInput := &core.OwnersRequest{Data: s.Response}

	respBytes, response, err := post("owners", ownersInput)
	if err != nil {
		t.Fatalf("Error getting owners, %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	var ownersData core.OwnersData
	if err = json.Unmarshal(respBytes, &ownersData); err != nil {
		t.Fatalf("Error getting owners, %v", err)
	}

	if ownersData.Status != "ok" {
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", ownersData.Status)
	}
	if len(ownersData.Owners) != 2 {
		t.Fatalf("Expected there to be 2 owners, got %d instead", len(ownersData.Owners))
	}
}

// Test that the /summary API endpoint works and returns data in the correct format.
func TestSummary(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check that summary works when no users have delegated.
	summaryInput := &core.SummaryRequest{Name: createVaultInput.Name, Password: createVaultInput.Password}

	respBytes, response, err := post("summary", summaryInput)
	if err != nil {
		t.Fatalf("Error getting summary, %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	var summaryData core.SummaryData
	if err = json.Unmarshal(respBytes, &summaryData); err != nil {
		t.Fatalf("Error getting owners, %v", err)
	}

	if summaryData.Status != "ok" {
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", summaryData.Status)
	}

	// Check that there are exactly 2 listings in All.
	if len(summaryData.All) != 2 {
		t.Fatalf("Expected there to be 2 listings in All, got %d instead", len(summaryData.All))
	}

	// Check user 1's listing.
	data, ok := summaryData.All[createUserInput1.Name]
	if !ok {
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createUserInput1.Name)
	}
	if data.Admin {
		t.Fatalf("Expected user \"%s\" to not be an admin", createUserInput1.Name)
	}
	if data.Type != "RSA" {
		t.Fatalf("Expected user \"%s\" to have type \"RSA\"", createUserInput1.Name)
	}

	// Check the admin user's listing.
	data, ok = summaryData.All[createVaultInput.Name]
	if !ok {
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createVaultInput.Name)
	}
	if !data.Admin {
		t.Fatalf("Expected user \"%s\" to be an admin", createVaultInput.Name)
	}
	if data.Type != "RSA" {
		t.Fatalf("Expected user \"%s\" to have type \"RSA\"", createVaultInput.Name)
	}

	// Check that there are no live users.
	if len(summaryData.Live) != 0 {
		t.Fatalf("Expected there to be 0 lives users, got %d instead", len(summaryData.Live))
	}

	// Delegate user 1 and check summary's response.
	if _, _, err := post("delegate", delegateInput1); err != nil {
		t.Fatalf("Error delegating user 1, %v", err)
	}

	respBytes, response, err = post("summary", summaryInput)
	if err != nil {
		t.Fatalf("Error getting summary, %v", err)
	}

	if response.StatusCode != 200 {
		t.Fatalf("Expected StatusCode 200, got %d instead", response.StatusCode)
	}

	if err = json.Unmarshal(respBytes, &summaryData); err != nil {
		t.Fatalf("Error getting owners, %v", err)
	}

	if summaryData.Status != "ok" {
		t.Fatalf("Expected Status \"ok\", got \"%s\" instead", summaryData.Status)
	}

	// Check that there is exacly one listing in Live
	if len(summaryData.Live) != 1 {
		t.Fatalf("Expected there to be 2 listings in Live, got %d instead", len(summaryData.Live))
	}

	// Check user 1's listing in Live
	_, ok = summaryData.Live[createUserInput1.Name]
	if !ok {
		t.Fatalf("Expected user \"%s\" to be listed in summary, but was not found", createUserInput1.Name)
	}
}

// Test that the /password API endpoint works and returns data in the correct format.
func TestPassword(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check changing password with invalid password.
	passwordInput := &core.PasswordRequest{
		Name:        createUserInput1.Name,
		Password:    "badpassword",
		NewPassword: "worsepassword",
	}
	if err := postAndTest("password", passwordInput, 200, "Wrong Password"); err != nil {
		t.Fatalf("Error changing password with invalid passsowrd, %v", err)
	}

	// Check changing password with nonexistent user.
	passwordInput = &core.PasswordRequest{
		Name:        createUserInput2.Name,
		Password:    "badpassword",
		NewPassword: "worsepassword",
	}
	if err := postAndTest("password", passwordInput, 200, "Record not present"); err != nil {
		t.Fatalf("Error changing password with nonexistent user, %v", err)
	}

	// Check changing the password properly.
	passwordInput = &core.PasswordRequest{
		Name:        createUserInput1.Name,
		Password:    createUserInput1.Password,
		NewPassword: "foobar",
	}
	if err := postAndTest("password", passwordInput, 200, "ok"); err != nil {
		t.Fatalf("Error changing password, %v", err)
	}
}

// Test that the /purge API endpoint works and returns data in the correct format.
func TestPurge(t *testing.T) {
	cmd := setup(t)
	defer teardown(t, cmd)

	// Create a vault/admin user and 1 normal user so there is data to work with.
	if _, _, err := post("create", createVaultInput); err != nil {
		t.Fatalf("Error creating vault, %v", err)
	}
	if _, _, err := post("create-user", createUserInput1); err != nil {
		t.Fatalf("Error creating user 1, %v", err)
	}

	// Check purging with non-admin user
	purgeInput := &core.PurgeRequest{
		Name:     createUserInput1.Name,
		Password: createUserInput1.Password,
	}
	if err := postAndTest("purge", purgeInput, 200, "Admin required"); err != nil {
		t.Fatalf("Error purging with non-admin user, %v", err)
	}

	// Check purging with admin user
	purgeInput = &core.PurgeRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
	}
	if err := postAndTest("purge", purgeInput, 200, "ok"); err != nil {
		t.Fatalf("Error purging with admin user, %v", err)
	}
}

////////////////////////////////////////////////////////////////////////////////
// Restore tests                                                              //
//                                                                            //
// These need to write files to disk in order to test recovering delegations. //
////////////////////////////////////////////////////////////////////////////////

var (
	restore *client.RemoteServer

	// restoreSecret is the encrypted data that should be decryptable
	// both before and after the restart.
	restoreSecret []byte

	restoreEncryptInput = &core.EncryptRequest{
		Minimum:  2,
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		Owners:   []string{createUserInput3.Name, createUserInput2.Name},
		Data:     []byte(base64.StdEncoding.EncodeToString([]byte(encryptMessage))),
	}
)

func restoreSetup(t *testing.T, configPath, vaultPath string) (cmd *exec.Cmd) {
	const maxAttempts = 5

	// Look for the redoctober binary in current directory and then in $GOPATH/bin
	binaryPath, err := exec.LookPath("./redoctober")
	if err != nil {
		goPathBinary := fmt.Sprintf("%s/bin/redoctober", os.Getenv("GOPATH"))
		binaryPath, err = exec.LookPath(goPathBinary)
		if err != nil {
			t.Fatalf(`Could not find redoctober binary at "./redoctober" or "%s"`, goPathBinary)
		}
	}

	cmd = exec.Command(binaryPath, "-vaultpath", vaultPath, "-f", configPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Error running redoctober command, %v", err)
	}

	attempts := 0

	for {
		resp, err := http.Get("http://localhost:8081")
		if err == nil {
			resp.Body.Close()
			break
		}

		attempts++
		if attempts > maxAttempts {
			t.Fatalf("failed to start redoctober (max connection attempts exceeded)")
		}
		time.Sleep(500 * time.Millisecond)
	}

	return
}

func tempName(t *testing.T) string {
	tmpf, err := ioutil.TempFile("", "redoctober_integration")
	if err != nil {
		t.Fatalf("failed to get a temporary file: %s", err)
	}

	name := tmpf.Name()
	tmpf.Close()
	return name
}

func TestRestore(t *testing.T) {
	// Set up the vault.
	pstore := tempName(t)
	defer os.Remove(pstore)

	cfgPath := tempName(t)
	defer os.Remove(cfgPath)

	prepareSetup(t, pstore, cfgPath)

	vaultPath := tempName(t)
	defer os.Remove(vaultPath)

	// Run the server, perform some delegations, then kill the
	// server.
	beforeRestartRestore(t, cfgPath, vaultPath)

	// The server has restarted --- verify that the persisted
	// delegations are available.
	afterRestartRestore(t, cfgPath, vaultPath)

	// Verify that we can reset the persisted delegations.
	afterRestartPurge(t, cfgPath, vaultPath)
}

func prepareSetup(t *testing.T, pstore, cfgPath string) {
	// Write the config file.
	cfg := config.New()
	cfg.Delegations = &config.Delegations{
		Persist:   true,
		Mechanism: persist.FileMechanism,
		Policy:    "(Alice & Bill)",
		Users:     []string{"Alice", "Bill"},
		Location:  pstore,
	}
	cfg.Server = &config.Server{
		Addr:      "localhost:8080",
		CertPaths: "testdata/server.crt",
		KeyPaths:  "testdata/server.pem",
	}
	cfg.Metrics = &config.Metrics{
		Host: "localhost",
		Port: "8081",
	}

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("failed to marshal config file: %s", err)
	}

	err = ioutil.WriteFile(cfgPath, out, 0644)
	if err != nil {
		t.Fatalf("failed to write config file: %s", err)
	}

	// We'll have two uses: one to permit the pre-restart decryption,
	// one to permit the post-restart decryption, and one to verify
	// the purge functionality.
	delegateInput1.Uses = 3
	delegateInput2.Uses = 3

	// Allow someone to decrypt.
	delegateInput1.Users = []string{createVaultInput.Name}
	delegateInput2.Users = []string{createVaultInput.Name}
}

func restoreCheckStatus(t *testing.T, expected string) {
	// Verify the vault is persisting.
	statusRequest := core.StatusRequest{
		Name:     createUserInput1.Name,
		Password: createUserInput1.Password,
	}

	var status core.StatusData
	var response core.ResponseData

	respBytes, _, err := post("status", statusRequest)
	if err != nil {
		t.Fatalf("status request failed: %s", err)
	} else if err = json.Unmarshal(respBytes, &response); err != nil {
		t.Fatalf("failed to unmarshal status request: %s", err)
	} else if response.Status != "ok" {
		t.Fatalf("status request failed: %s", response.Status)
	} else if err = json.Unmarshal(response.Response, &status); err != nil {
		t.Fatalf("failed to unmarshal status response data: %s", err)
	} else if status.Status != expected {
		t.Fatalf("server delegation persistence should be %s but is %s", expected, status.Status)
	}
}

func restoreCheckLiveCount(t *testing.T, expected int) {
	// Verify the vault is persisting.
	summaryRequest := core.SummaryRequest{
		Name:     createUserInput1.Name,
		Password: createUserInput1.Password,
	}

	var summary core.SummaryData
	respBytes, _, err := post("summary", summaryRequest)
	if err != nil {
		t.Fatalf("summary request failed: %s", err)
	} else if err = json.Unmarshal(respBytes, &summary); err != nil {
		t.Fatalf("failed to unmarshal summary response data: %s", err)
	} else if summary.Status != "ok" {
		t.Fatalf("summary request failed: %s", summary.Status)
	} else if len(summary.Live) != expected {
		t.Fatalf("expected %d delegations to be live but have %d", expected, len(summary.Live))
	}
}

func restoreCheckLiveUsers(t *testing.T, present, absent []string) {
	// Verify the vault is persisting.
	summaryRequest := core.SummaryRequest{
		Name:     createUserInput1.Name,
		Password: createUserInput1.Password,
	}

	var summary core.SummaryData
	respBytes, _, err := post("summary", summaryRequest)
	if err != nil {
		t.Fatalf("summary request failed: %s", err)
	} else if err = json.Unmarshal(respBytes, &summary); err != nil {
		t.Fatalf("failed to unmarshal summary response data: %s", err)
	} else if summary.Status != "ok" {
		t.Fatalf("summary request failed: %s", summary.Status)
	}

	for _, user := range present {
		if _, ok := summary.Live[user]; !ok {
			t.Fatalf("%s should be in the active delegations, but isn't", user)
		}
	}

	for _, user := range absent {
		if _, ok := summary.Live[user]; ok {
			t.Fatalf("%s shouldn't be in the active delegations, but is", user)
		}
	}
}

func beforeRestartRestore(t *testing.T, cfgPath, vaultPath string) {
	cmd := restoreSetup(t, cfgPath, vaultPath)
	defer teardown(t, cmd)

	srv, err := client.NewRemoteServer("localhost:8080", "testdata/server.crt")
	if err != nil {
		t.Fatalf("failed to set up client: %s", err)
	}

	// Create a vault/admin user and 2 normal users so there is data to work with.
	if _, _, err = post("create", createVaultInput); err != nil {
		t.Fatalf("failed to create the vault: %s", err)
	}

	if _, err = srv.CreateUser(*createUserInput1); err != nil {
		t.Fatalf("couldn't create user %s: %s", createUserInput1.Name, err)
	}
	if _, err = srv.CreateUser(*createUserInput2); err != nil {
		t.Fatalf("couldn't create user %s: %s", createUserInput2.Name, err)
	}
	if _, err = srv.CreateUser(*createUserInput3); err != nil {
		t.Fatalf("couldn't create user %s: %s", createUserInput3.Name, err)
	}

	// A newly-created vault with a valid persistence config
	// should be persisting.
	restoreCheckStatus(t, persist.Active)

	// Delegate two users.
	if _, err = srv.Delegate(*delegateInput2); err != nil {
		t.Fatalf("failed to delegate for %s: %s", delegateInput2.Name, err)
	}
	if _, err = srv.Delegate(*delegateInput3); err != nil {
		t.Fatalf("failed to delegate for %s: %s", delegateInput3.Name, err)
	}

	restoreCheckLiveCount(t, 2)
	restoreCheckLiveUsers(t, []string{delegateInput2.Name, delegateInput3.Name},
		[]string{createUserInput1.Name, createVaultInput.Name})

	// Encrypt a message, and make sure it can be decrypted.
	resp, err := srv.Encrypt(*restoreEncryptInput)
	restoreSecret = resp.Response

	decryptInput := &core.DecryptRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		Data:     restoreSecret[:],
	}

	decrypted, err := srv.DecryptIntoData(*decryptInput)
	if err != nil {
		t.Fatalf("failed to decrypt message: %s", err)
	}

	decryptedMessage, err := base64.StdEncoding.DecodeString(string(decrypted))
	if err != nil {
		t.Fatalf("DecodeString failed: %s", err)
	}

	if string(decryptedMessage) != encryptMessage {
		t.Fatalf("decryption produced the wrong message: want '%s' but have '%s'",
			encryptMessage, decryptedMessage)
	}
}

func afterRestartRestore(t *testing.T, cfgPath, vaultPath string) {
	cmd := restoreSetup(t, cfgPath, vaultPath)
	defer teardown(t, cmd)

	srv, err := client.NewRemoteServer("localhost:8080", "testdata/server.crt")
	if err != nil {
		t.Fatalf("failed to set up client: %s", err)
	}

	// An existing vault with a persisted delegation store should
	// be inactive.
	restoreCheckStatus(t, persist.Inactive)

	// Delegate a user who wasn't in the persisted delegation set.
	if _, err := srv.Delegate(*delegateInput1); err != nil {
		t.Fatalf("error delegating with user 1, %v", err)
	}

	restoreCheckLiveCount(t, 1)
	restoreCheckLiveUsers(t, []string{delegateInput1.Name},
		[]string{createUserInput2.Name, delegateInput3.Name, createVaultInput.Name})

	// Begin the restoration by delegating for a single user.
	if _, err := srv.Restore(*delegateInput1); err != nil {
		t.Fatalf("restoration by user %s failed: %s", delegateInput1.Name, err)
	}

	// The vault should not have been restored yet.
	restoreCheckStatus(t, persist.Inactive)
	restoreCheckLiveCount(t, 1)
	restoreCheckLiveUsers(t, []string{delegateInput1.Name},
		[]string{createUserInput2.Name, delegateInput3.Name, createVaultInput.Name})

	// Delegate the second user, which should lead to restoring
	// the delegations.
	if _, err := srv.Restore(*delegateInput4); err != nil {
		t.Fatalf("restoration by user %s failed: %s", delegateInput1.Name, err)
	}

	restoreCheckStatus(t, persist.Active)
	restoreCheckLiveCount(t, 2)
	restoreCheckLiveUsers(t, []string{delegateInput2.Name, delegateInput3.Name},
		[]string{createUserInput1.Name, createVaultInput.Name})

	decryptInput := &core.DecryptRequest{
		Name:     createVaultInput.Name,
		Password: createVaultInput.Password,
		Data:     restoreSecret[:],
	}

	decrypted, err := srv.DecryptIntoData(*decryptInput)
	if err != nil {
		t.Fatalf("failed to decrypt message: %s", err)
	}

	decryptedMessage, err := base64.StdEncoding.DecodeString(string(decrypted))
	if err != nil {
		t.Fatalf("DecodeString failed: %s", err)
	}
	if string(decryptedMessage) != encryptMessage {
		t.Fatalf("decryption produced the wrong message: want '%s' but have '%s'",
			encryptMessage, decryptedMessage)
	}
}

func afterRestartPurge(t *testing.T, cfgPath, vaultPath string) {
	cmd := restoreSetup(t, cfgPath, vaultPath)
	defer teardown(t, cmd)

	srv, err := client.NewRemoteServer("localhost:8080", "testdata/server.crt")
	if err != nil {
		t.Fatalf("failed to set up client: %s", err)
	}

	// An existing vault with a persisted delegation store should
	// be inactive.
	restoreCheckStatus(t, persist.Inactive)

	resp, err := srv.ResetPersisted(core.PurgeRequest{Name: createVaultInput.Name, Password: createVaultInput.Password})
	if err != nil {
		t.Fatalf("failed to reset persisted delegations: %s", err)
	}

	if resp.Status != "ok" {
		t.Fatalf("failed to reset persisted delegations: %s", resp.Status)
	}

	// An existing vault whose persistence store has been reset
	// should be active.
	restoreCheckStatus(t, persist.Active)
}
