// Copyright 2021 RetailNext, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package gcpkms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"filippo.io/age"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func rsaPublicKeyToPEM(t *testing.T, key *rsa.PublicKey) []byte {
	t.Helper()
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubKeyBytes})
}

// TestParsePEMEncodedRSAPublicKey_Valid tests successful parsing.
func TestParsePEMEncodedRSAPublicKey_Valid(t *testing.T) {
	key := generateTestKey(t)
	pemBytes := rsaPublicKeyToPEM(t, &key.PublicKey)

	parsed, err := parsePEMEncodedRSAPublicKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.N.Cmp(key.PublicKey.N) != 0 || parsed.E != key.PublicKey.E {
		t.Error("parsed public key does not match original")
	}
}

// TestParsePEMEncodedRSAPublicKey_NoPEM tests that empty input returns an error.
func TestParsePEMEncodedRSAPublicKey_NoPEM(t *testing.T) {
	_, err := parsePEMEncodedRSAPublicKey([]byte("not pem data"))
	if err == nil {
		t.Error("expected error for non-PEM input")
	}
}

// TestParsePEMEncodedRSAPublicKey_WrongType tests that a PEM block with an
// unexpected type is rejected.
func TestParsePEMEncodedRSAPublicKey_WrongType(t *testing.T) {
	key := generateTestKey(t)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	// Use a type that doesn't match the expected "RSA PUBLIC KEY"
	wrongTypePEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	_, err = parsePEMEncodedRSAPublicKey(wrongTypePEM)
	if err == nil {
		t.Error("expected error for wrong PEM block type")
	}
}

// TestKeyIDDeterministic verifies that keyID returns the same value for the same key.
func TestKeyIDDeterministic(t *testing.T) {
	key := generateTestKey(t)

	id1, err := keyID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := keyID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Error("keyID is not deterministic for the same key")
	}
}

// TestKeyIDUniquePerKey verifies that different keys produce different IDs.
func TestKeyIDUniquePerKey(t *testing.T) {
	key1 := generateTestKey(t)
	key2 := generateTestKey(t)

	id1, err := keyID(&key1.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	id2, err := keyID(&key2.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Error("different keys produced the same key ID")
	}
}

// TestCRC32C verifies that crc32c is deterministic.
func TestCRC32C(t *testing.T) {
	data := []byte("hello world")
	c1 := crc32c(data)
	c2 := crc32c(data)
	if c1 != c2 {
		t.Error("crc32c is not deterministic")
	}
	if crc32c([]byte("different")) == c1 {
		t.Error("crc32c produced same value for different inputs")
	}
}

// TestCRC32C_KnownValue checks against a known CRC32C value.
func TestCRC32C_KnownValue(t *testing.T) {
	// CRC32C of "123456789" is 0xE3069283 (standard test vector)
	got := crc32c([]byte("123456789"))
	const want uint32 = 0xE3069283
	if got != want {
		t.Errorf("crc32c(\"123456789\") = 0x%X, want 0x%X", got, want)
	}
}

// newTestClient creates a client with a populated nameByKeyID without a real
// KMS connection. kmsClient is left nil; tests must only exercise code paths
// that do not reach the KMS RPC.
func newTestClient(nameByKeyID map[string]string) *client {
	return &client{
		kmsClient:   nil,
		nameByKeyID: nameByKeyID,
	}
}

// TestUnwrap_NoMatchingStanzas verifies ErrIncorrectIdentity when no stanzas match.
func TestUnwrap_NoMatchingStanzas(t *testing.T) {
	c := newTestClient(map[string]string{})
	_, err := c.Unwrap([]*age.Stanza{})
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("expected ErrIncorrectIdentity, got %v", err)
	}
}

// TestUnwrap_WrongStanzaType verifies that non-matching stanza types are skipped.
func TestUnwrap_WrongStanzaType(t *testing.T) {
	c := newTestClient(map[string]string{})
	stanzas := []*age.Stanza{
		{Type: "X25519", Args: []string{"somekey"}},
	}
	_, err := c.Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("expected ErrIncorrectIdentity, got %v", err)
	}
}

// TestUnwrap_InvalidArgCount verifies that a stanza with wrong arg count returns an error.
func TestUnwrap_InvalidArgCount(t *testing.T) {
	c := newTestClient(map[string]string{})
	stanzas := []*age.Stanza{
		{Type: "kms-rsa-oaep-sha256", Args: []string{"key1", "key2"}},
	}
	_, err := c.Unwrap(stanzas)
	if err == nil {
		t.Error("expected error for stanza with wrong arg count")
	}
	if errors.Is(err, age.ErrIncorrectIdentity) {
		t.Error("expected a specific error, not ErrIncorrectIdentity")
	}
}

// TestUnwrap_KeyIDNotFound verifies ErrIncorrectIdentity when the key ID is not
// in the client's known keys.
func TestUnwrap_KeyIDNotFound(t *testing.T) {
	c := newTestClient(map[string]string{"otherkeyid": "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"})
	stanzas := []*age.Stanza{
		{Type: "kms-rsa-oaep-sha256", Args: []string{"unknownkeyid"}, Body: []byte("ciphertext")},
	}
	_, err := c.Unwrap(stanzas)
	if !errors.Is(err, age.ErrIncorrectIdentity) {
		t.Errorf("expected ErrIncorrectIdentity, got %v", err)
	}
}
