// Copyright 2021 RetailNext, Inc. All rights reserved.
// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcpkms

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"hash/crc32"

	kms "cloud.google.com/go/kms/apiv1"
	"filippo.io/age"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func keyID(key *rsa.PublicKey) (string, error) {
	keyBytes, err := asn1.Marshal(key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(keyBytes)
	return base64.StdEncoding.EncodeToString(digest[:]), nil
}

// NewClient creates an age.Identity that decrypts using Google Cloud KMS.
// Only `RSA_DECRYPT_OAEP_*_SHA256` keys are supported.
// All decrypt operations use the context provided to NewClient.
// The underlying KeyManagementClient retains connection resources until
// Close is called on the Client.
func NewClient(ctx context.Context, names []string) (Client, error) {
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}
	cl := client{
		kmsClient:   kmsClient,
		ctx:         ctx,
		nameByKeyID: make(map[string]string, len(names)),
	}
	for _, name := range names {
		if err := cl.addKey(ctx, name); err != nil {
			return nil, fmt.Errorf("problem with key %q: %w", name, err)
		}
	}
	return &cl, nil
}

// Client is an age.Identity that needs to be closed after use.
type Client interface {
	Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error)
	Close() error
}

type client struct {
	kmsClient   *kms.KeyManagementClient
	ctx         context.Context
	nameByKeyID map[string]string
}

func parsePEMEncodedRSAPublicKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM blocks found")
	}
	if block.Type != "RSA PUBLIC KEY" {
		return nil, fmt.Errorf("found unexpected %q PEM block", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	if pubKey, ok := parsed.(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("failed to parse %q", block.Type)
	} else {
		return pubKey, nil
	}
}

func (c *client) addKey(ctx context.Context, name string) error {
	resp, err := c.kmsClient.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: name})
	if err != nil {
		return err
	}

	switch resp.Algorithm {
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_2048_SHA256:
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_3072_SHA256:
	case kmspb.CryptoKeyVersion_RSA_DECRYPT_OAEP_4096_SHA256:
	default:
		return fmt.Errorf("unsupported key type: %s", resp.Algorithm.String())
	}

	key, err := parsePEMEncodedRSAPublicKey([]byte(resp.Pem))
	if err != nil {
		return err
	}
	id, err := keyID(key)
	if err != nil {
		return err
	}
	c.nameByKeyID[id] = resp.Name
	return nil
}

func crc32c(data []byte) uint32 {
	t := crc32.MakeTable(crc32.Castagnoli)
	return crc32.Checksum(data, t)
}

func (c *client) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	for _, stanza := range stanzas {
		if stanza.Type != "kms-rsa-oaep-sha256" {
			continue
		}
		if len(stanza.Args) != 1 {
			return nil, fmt.Errorf("invalid kms-rsa-oaep-sha256 recipient")
		}

		name, ok := c.nameByKeyID[stanza.Args[0]]
		if !ok {
			continue
		}

		req := &kmspb.AsymmetricDecryptRequest{
			Name:             name,
			Ciphertext:       stanza.Body,
			CiphertextCrc32C: wrapperspb.Int64(int64(crc32c(stanza.Body))),
		}
		resp, err := c.kmsClient.AsymmetricDecrypt(c.ctx, req)
		if err != nil {
			return nil, err
		}
		return resp.Plaintext, nil
	}
	return nil, age.ErrIncorrectIdentity
}

func (c *client) Close() error {
	return c.kmsClient.Close()
}
