package roagent

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"

	"github.com/cloudflare/redoctober/client"
	"github.com/cloudflare/redoctober/core"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type ROSigner struct {
	server       *client.RemoteServer
	pub          ssh.PublicKey
	encryptedKey []byte
	user         string
	pswd         string
}

func (signer ROSigner) PublicKey() ssh.PublicKey {
	return signer.pub
}

func (signer ROSigner) Sign(rand io.Reader, msg []byte) (signature *ssh.Signature, err error) {
	req := core.DecryptSignRequest{
		Name:     signer.user,
		Password: signer.pswd,
		Data:     signer.encryptedKey,
		TBSData:  msg,
	}

	resp, err := signer.server.DecryptSign(req)
	if err != nil {
		return nil, err
	}
	if resp.Status != "ok" {
		log.Fatal("response status error:", resp.Status)
		return nil, errors.New("response status error")
	}
	fmt.Println("Response Status:", resp.Status)

	var respMsg core.DecryptSignWithDelegates
	err = json.Unmarshal(resp.Response, &respMsg)
	if err != nil {
		return nil, err
	}

	var respSignature ssh.Signature
	err = json.Unmarshal(resp.Response, &respSignature)
	if err != nil {
		return nil, err
	}

	return &respSignature, nil
}

type ROAgent struct {
	signer ROSigner
}

func NewROAgent(server *client.RemoteServer, pubKey ssh.PublicKey, encryptedPrivKey []byte, user, pswd string) agent.Agent {
	return &ROAgent{
		ROSigner{
			server,
			pubKey,
			encryptedPrivKey,
			user,
			pswd,
		},
	}
}

func (r *ROAgent) RemoveAll() error {
	return nil
}

// Remove removes all identities with the given public key.
func (r *ROAgent) Remove(key ssh.PublicKey) error {
	return nil
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list.
func (r *ROAgent) Lock(passphrase []byte) error {
	return nil
}

// Unlock undoes the effect of Lock
func (r *ROAgent) Unlock(passphrase []byte) error {
	return nil
}

// List returns the identities known to the agent.
func (r *ROAgent) List() ([]*agent.Key, error) {
	return []*agent.Key{
		{
			Format:  r.signer.PublicKey().Type(),
			Blob:    r.signer.PublicKey().Marshal(),
			Comment: "",
		},
	}, nil
}

// Insert adds a private key to the ROAgent. If a certificate
// is given, that certificate is added as public key. Note that
// any constraints given are ignored.
func (r *ROAgent) Add(key agent.AddedKey) error {
	return nil
}

// Sign returns a signature for the data.
func (r *ROAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	wanted := key.Marshal()
	if bytes.Equal(r.signer.PublicKey().Marshal(), wanted) {
		return r.signer.Sign(rand.Reader, data)
	}
	return nil, errors.New("wrong key requested")
}

// Signers returns signers for all the known keys.
func (r *ROAgent) Signers() ([]ssh.Signer, error) {
	return []ssh.Signer{r.signer}, nil
}
