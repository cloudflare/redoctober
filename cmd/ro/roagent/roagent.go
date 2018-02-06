// Package roagent provides ROAgent, which implements the SSH agent interface,
// forwarding sign requests to a Red October server

package roagent

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"io"

	roclient "github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"golang.org/x/crypto/ssh"
)

type ROAgent struct {
	locked   bool
	keyring  []*ROSigner

	server   *roclient.RemoteServer
	username string
	password string
}

type ROSigner struct {
	pub     ssh.PublicKey
	encKey  []byte
	roagent *ROAgent
	comment string
}

func (rosigner ROSigner) PublicKey() ssh.PublicKey {
	return rosigner.pub
}

func (rosigner ROSigner) Sign(rand io.Reader, msg []byte) (signature *ssh.Signature, err error) {
	req := core.SSHSignWithRequest{
		Name:     rosigner.roagent.username,
		Password: rosigner.roagent.password,
		Data:     rosigner.encKey,
		TBSData:  msg,
	}

	resp, err := rosigner.roagent.server.SSHSignWith(req)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		return nil, errors.New("ro-ssh-agent: response status error: " + resp.Status)
	}

	var respMsg core.SSHSignatureWithDelegates
	err = json.Unmarshal(resp.Response, &respMsg)
	if err != nil {
		return nil, err
	}
	sshSignature := ssh.Signature{
		Format: respMsg.SignatureFormat,
		Blob:   respMsg.Signature,
	}
	return &sshSignature, nil
}

// NewROAgent creates a new SSH agent which forwards signature requests to the
// provided remote server
func NewROAgent(server *roclient.RemoteServer, username, password string) *ROAgent {
	return &ROAgent{
		server:   server,
		username: username,
		password: password,
		keyring:  []*ROSigner{},
	}
}

// NewROSigner adds a new SSH identity to the ROAgent
func NewROSigner(pubKey ssh.PublicKey, encBytes []byte) *ROSigner {
	return &ROSigner{
		pub:    pubKey,
		encKey: encBytes,
	}
}

// RemoveAll empties ROAgent's keyring
func (roagent *ROAgent) RemoveAll() error {
	if roagent.locked {
		return errLocked
	}
	roagent.keyring = []*ROSigner{}
	return nil
}

// Removes the first matching key from ROAgent's keyring
func (roagent *ROAgent) Remove(key ssh.PublicKey) error {
	if roagent.locked {
		return errLocked
	}
	wanted := key.Marshal()
	for i, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			// Order is not preserved
			roagent.keyring[i] = roagent.keyring[0] 
			roagent.keyring = roagent.keyring[1:]
			log.Println("ro-ssh-agent: signer removed")
			return nil
		}
	}
	return errors.New("ro-ssh-agent: could not remove signer")
}

// Locks the ROAgent by removing the password
// TODO should this encrypt the password instead?
func (roagent *ROAgent) Lock(passphrase []byte) error {
	if roagent.locked {
		return errLocked
	}
	if len(passphrase) != len(roagent.password) || 1 != subtle.ConstantTimeCompare(passphrase, []byte(roagent.password)) {
		roagent.password = ""
		roagent.locked = true
		return nil
	}
	return errors.New("ro-ssh-agent: could not lock the agent")
}

// Unlocks the ROAgent by changing the password
// FIXME ask papa RO if the password is correct
func (roagent *ROAgent) Unlock(passphrase []byte) error {
	if !roagent.locked {
		return errors.New("ro-ssh-agent: agent is not locked")
	}
	roagent.locked = false
	roagent.password = string(passphrase)
	return nil
}

// List returns the identities known to the agent.
func (roagent *ROAgent) List() ([]*Key, error) {
	if roagent.locked {
		// section 2.7: locked agents return empty.
		return nil, nil
	}

	list := make([]*Key, len(roagent.keyring))
	for i, rosigner := range roagent.keyring {
		list[i] = &Key{
			Format:  rosigner.PublicKey().Type(),
			Blob:    rosigner.PublicKey().Marshal(),
			Comment: roagent.username,
		}
	}
	return list, nil
}

// Adds a new encrypted key to ROAgent's keyring
func (roagent *ROAgent) Add(key AddedKey) error {
	if roagent.locked {
		return errLocked
	}

	rosigner := key.PrivateKey.(*ROSigner)
	rosigner.roagent = roagent
	roagent.keyring = append(roagent.keyring, rosigner)
	log.Println("new signer was added. Total:", len(roagent.keyring))
	return nil
}

// Sign returns a signature for the data.
func (roagent *ROAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	if roagent.locked {
		return nil, errLocked
	}

	wanted := key.Marshal()
	for _, rosigner := range roagent.keyring {
		if bytes.Equal(rosigner.PublicKey().Marshal(), wanted) {
			rosigner.roagent = roagent
			return rosigner.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("key not found on keyring")
}

// Signers returns signers for all the known keys.
func (roagent *ROAgent) Signers() ([]ssh.Signer, error) {
	if roagent.locked {
		return nil, errLocked
	}

	list := make([]ssh.Signer, len(roagent.keyring))
	for i, rosigner := range roagent.keyring {
		rosigner.roagent = roagent
		list[i] = ssh.Signer(rosigner)
	}
	return list, nil
}
