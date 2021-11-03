// Copyright 2021 RetailNext, Inc. All rights reserved.
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsaoaep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"

	"filippo.io/age"
)

// NewRecipient creates an age.Recipient representing an RSA public key.
//
// The file keys are encrypted using OAEP with SHA256. This implementation
// differs from agessh's support for RSA public keys by not including an AEAD
// "label" in the OAEP encryption because Google Cloud KMS' asymmetric
// decryption API does not allow specifying a label during decryption.
//
// This implementation also uses a different stanza Type and a different
// form of key identification.
func NewRecipient(key *rsa.PublicKey) (age.Recipient, error) {
	keyID, err := keyID(key)
	if err != nil {
		return nil, err
	}
	return &recipient{
		key:   key,
		keyID: keyID,
	}, nil
}

func keyID(key *rsa.PublicKey) (string, error) {
	keyBytes, err := asn1.Marshal(key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(keyBytes)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

type recipient struct {
	key   *rsa.PublicKey
	keyID string
}

func (r *recipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	l := &age.Stanza{
		Type: "kms-rsa-oaep-sha256",
		Args: []string{r.keyID},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.key, fileKey, nil)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return []*age.Stanza{l}, nil
}
