// Copyright 2012 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package roagent

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"

	"golang.org/x/crypto/ssh"
)

const SSHROKey string = "ssh-ro"

var errLocked = errors.New("agent: locked")

// Server wraps an Agent and uses it to implement the agent side of
// the SSH-agent, wire protocol.
type server struct {
	roagent *ROAgent
}

func parseROSigner(req []byte) (*AddedKey, error) {
	var k roSignerMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(k.Pub)
	if err != nil {
		return nil, errors.New("received ill-formatted public key")
	}

	return &AddedKey{
		PrivateKey: &ROSigner{
			pub:    pubKey,
			encKey: k.EncKey,
		},
		Comment: k.Comments,
	}, nil
}

func (s *server) insertIdentity(req []byte) error {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	// FIXME what is record?
	if err := ssh.Unmarshal(req, &record); err != nil {
		return err
	}

	var addedKey *AddedKey
	var err error

	if record.Type == SSHROKey {
		addedKey, err = parseROSigner(req)
	} else {
		return errors.New("roagent can only accept keys encrypted by a Red October server")
	}

	if err != nil {
		return err
	}
	return s.roagent.Add(*addedKey)
}

func (s *server) processRequestBytes(reqData []byte) []byte {
	rep, err := s.processRequest(reqData)
	if err != nil {
		if err != errLocked {
			// TODO(hanwen): provide better logging interface?
			log.Printf("agent %d: %v", reqData[0], err)
		}
		return []byte{agentFailure}
	}

	if err == nil && rep == nil {
		return []byte{agentSuccess}
	}

	return ssh.Marshal(rep)
}

func marshalKey(k *Key) []byte {
	var record struct {
		Blob    []byte
		Comment string
	}
	record.Blob = k.Marshal()
	record.Comment = k.Comment

	return ssh.Marshal(&record)
}

// See [PROTOCOL.agent], section 2.5.1.
const agentV1IdentitiesAnswer = 2

type agentV1IdentityMsg struct {
	Numkeys uint32 `sshtype:"2"`
}

type agentRemoveIdentityMsg struct {
	KeyBlob []byte `sshtype:"18"`
}

type agentLockMsg struct {
	Passphrase []byte `sshtype:"22"`
}

type agentUnlockMsg struct {
	Passphrase []byte `sshtype:"23"`
}

func (s *server) processRequest(data []byte) (interface{}, error) {
	switch data[0] {
	case agentRequestV1Identities:
		return &agentV1IdentityMsg{0}, nil

	case agentRemoveAllV1Identities:
		return nil, nil

	case agentRemoveIdentity:
		var req agentRemoveIdentityMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		return nil, s.roagent.Remove(&Key{Format: wk.Format, Blob: req.KeyBlob})

	case agentRemoveAllIdentities:
		return nil, s.roagent.RemoveAll()

	case agentLock:
		var req agentLockMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		return nil, s.roagent.Lock(req.Passphrase)

	case agentUnlock:
		var req agentUnlockMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}
		return nil, s.roagent.Unlock(req.Passphrase)

	case agentSignRequest:
		var req signRequestAgentMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		k := &Key{
			Format: wk.Format,
			Blob:   req.KeyBlob,
		}

		sig, err := s.roagent.Sign(k, req.Data) //  TODO(hanwen): flags.
		if err != nil {
			return nil, err
		}
		return &signResponseAgentMsg{SigBlob: ssh.Marshal(sig)}, nil

	case agentRequestIdentities:
		keys, err := s.roagent.List()
		if err != nil {
			return nil, err
		}

		rep := identitiesAnswerAgentMsg{
			NumKeys: uint32(len(keys)),
		}
		for _, k := range keys {
			rep.Keys = append(rep.Keys, marshalKey(k)...)
		}
		return rep, nil

	case agentAddIDConstrained, agentAddIdentity:
		return nil, s.insertIdentity(data)
	}

	return nil, fmt.Errorf("unknown opcode %d", data[0])
}

func parseConstraints(constraints []byte) (lifetimeSecs uint32, confirmBeforeUse bool, extensions []ConstraintExtension, err error) {
	for len(constraints) != 0 {
		switch constraints[0] {
		case agentConstrainLifetime:
			lifetimeSecs = binary.BigEndian.Uint32(constraints[1:5])
			constraints = constraints[5:]
		case agentConstrainConfirm:
			confirmBeforeUse = true
			constraints = constraints[1:]
		case agentConstrainExtension:
			var msg constrainExtensionAgentMsg
			if err = ssh.Unmarshal(constraints, &msg); err != nil {
				return 0, false, nil, err
			}
			extensions = append(extensions, ConstraintExtension{
				ExtensionName:    msg.ExtensionName,
				ExtensionDetails: msg.ExtensionDetails,
			})
			constraints = msg.Rest
		default:
			return 0, false, nil, fmt.Errorf("unknown constraint type: %d", constraints[0])
		}
	}
	return
}

func setConstraints(key *AddedKey, constraintBytes []byte) error {
	lifetimeSecs, confirmBeforeUse, constraintExtensions, err := parseConstraints(constraintBytes)
	if err != nil {
		return err
	}

	key.LifetimeSecs = lifetimeSecs
	key.ConfirmBeforeUse = confirmBeforeUse
	key.ConstraintExtensions = constraintExtensions
	return nil
}

// ServeAgent serves the agent protocol on the given connection. It
// returns when an I/O error occurs.
func ServeAgent(roagent *ROAgent, c io.ReadWriter) error {
	s := &server{roagent}

	var length [4]byte
	for {
		if _, err := io.ReadFull(c, length[:]); err != nil {
			return err
		}
		l := binary.BigEndian.Uint32(length[:])
		if l > maxAgentResponseBytes {
			// We also cap requests.
			return fmt.Errorf("agent: request too large: %d", l)
		}

		req := make([]byte, l)
		if _, err := io.ReadFull(c, req); err != nil {
			return err
		}

		repData := s.processRequestBytes(req)
		if len(repData) > maxAgentResponseBytes {
			return fmt.Errorf("agent: reply too large: %d bytes", len(repData))
		}

		binary.BigEndian.PutUint32(length[:], uint32(len(repData)))
		if _, err := c.Write(length[:]); err != nil {
			return err
		}
		if _, err := c.Write(repData); err != nil {
			return err
		}
	}
}
