// Package roagent provides ROAgent, which implements the SSH agent interface,
// forwarding sign requests to a Red October server
package roagent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log"
	"io"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ROAgent struct {
	server       *client.RemoteServer
	user         string
	pswd         string
	keyring      []*ROSigner
}

type ROSigner struct {
	agent        *ROAgent
	pub          ssh.PublicKey
	rawKey       []byte
	encryptedKey []byte
}

func (signer ROSigner) PublicKey() ssh.PublicKey {
	return signer.pub
}

func (signer ROSigner) Sign(rand io.Reader, msg []byte) (signature *ssh.Signature, err error) {
	// TODO encryptedKey vs rawKey
	req := core.SSHSignWithRequest{
		Name:     signer.agent.user,
		Password: signer.agent.pswd,
		Data:     signer.encryptedKey,
		TBSData:  msg,
	}

	resp, err := signer.agent.server.SSHSignWith(req)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		return nil, errors.New("response status error: " + resp.Status)
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
func NewROAgent(server *client.RemoteServer, pubKey ssh.PublicKey, encryptedPrivKey []byte, user, pswd string) (agent.Agent, error) {
	// FIXME these arguments are extra
	roagent := &ROAgent{
		server,
		user,
		pswd,
		[]*ROSigner{},
	}

	err := roagent.AddROSigner(pubKey, encryptedPrivKey)
	if err != nil {
		return nil, errors.New("failed to add new signer to the ROAgent")
	}

	return roagent, nil
}

// NewROSigner adds a new SSH identity to the ROAgent
func (r *ROAgent) AddROSigner(pubKey ssh.PublicKey, encryptedPrivKey []byte) error {
	rosigner := &ROSigner{
		agent:        r,
		pub:          pubKey,
		encryptedKey: encryptedPrivKey,
	}
	r.keyring = append(r.keyring, rosigner)
	return nil
}

// RemoveAll empties ROAgent's keyring
func (r *ROAgent) RemoveAll() error {
	r.keyring = []*ROSigner{}
	return nil
}

// Removes the first matching key from ROAgent's keyring
func (r *ROAgent) Remove(key ssh.PublicKey) error {
	wanted := key.Marshal()
	for i, signer := range r.keyring {
		if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
			// Order is not preserved
			r.keyring[i] = r.keyring[0] 
			r.keyring = r.keyring[1:]
			log.Println("signer was removed")
			return nil
		}
	}
	return errors.New("could not remove signer")
}

// Locks the ROAgent by removing the password
// TODO should this encrypt the password instead?
func (r *ROAgent) Lock(passphrase []byte) error {
	if bytes.Equal(passphrase, []byte(r.pswd)) {
		r.pswd = ""
		return nil
	}
	return errors.New("could not lock the agent")
}

// Unlocks the ROAgent by adding the password
// FIXME ask papa RO if the password is correct
func (r *ROAgent) Unlock(passphrase []byte) error {
	r.pswd = string(passphrase)
	return nil
}

// List returns the identities known to the agent.
func (r *ROAgent) List() ([]*agent.Key, error) {
	list := make([]*agent.Key, len(r.keyring))
	for i, signer := range r.keyring {
		list[i] = &agent.Key{
			Format:  signer.PublicKey().Type(),
			Blob:    signer.PublicKey().Marshal(),
			Comment: r.user,
		}
	}
	return list, nil
}

// Add has no effect for the ROAgent
// FIXME
func (r *ROAgent) Add(key agent.AddedKey) error {
	signer, _ := ssh.NewSignerFromKey(key.PrivateKey)
	rosigner := &ROSigner{
		pub:          signer.PublicKey(),
		encryptedKey: nil, //[]byte
	}
	r.keyring = append(r.keyring, rosigner)
	log.Println("new signer was added")
	return nil
}

// Sign returns a signature for the data.
func (r *ROAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	wanted := key.Marshal()
	for _, signer := range r.keyring {
		if bytes.Equal(signer.PublicKey().Marshal(), wanted) {
			return signer.Sign(rand.Reader, data)
		}
	}
	return nil, errors.New("requested key was not found on keyring")
}

// Signers returns signers for all the known keys.
func (r *ROAgent) Signers() ([]ssh.Signer, error) {
	list := make([]ssh.Signer, len(r.keyring))
	for i, signer := range r.keyring {
		list[i] = ssh.Signer(signer)
	}
	return list, nil
}
