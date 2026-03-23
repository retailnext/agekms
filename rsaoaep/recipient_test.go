// Copyright 2021 RetailNext, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package rsaoaep

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func generateTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestNewRecipient(t *testing.T) {
	key := generateTestKey(t)
	r, err := NewRecipient(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if r == nil {
		t.Fatal("expected non-nil recipient")
	}
}

func TestWrapStanzaType(t *testing.T) {
	key := generateTestKey(t)
	r, err := NewRecipient(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(stanzas) != 1 {
		t.Fatalf("expected 1 stanza, got %d", len(stanzas))
	}
	if stanzas[0].Type != "kms-rsa-oaep-sha256" {
		t.Errorf("expected type %q, got %q", "kms-rsa-oaep-sha256", stanzas[0].Type)
	}
}

func TestWrapStanzaArgIsKeyID(t *testing.T) {
	key := generateTestKey(t)

	expectedID, err := keyID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewRecipient(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	if len(stanzas[0].Args) != 1 {
		t.Fatalf("expected 1 arg, got %d", len(stanzas[0].Args))
	}
	if stanzas[0].Args[0] != expectedID {
		t.Errorf("stanza arg %q != key ID %q", stanzas[0].Args[0], expectedID)
	}
}

func TestWrapBodyDecryptsCorrectly(t *testing.T) {
	key := generateTestKey(t)
	r, err := NewRecipient(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}

	stanzas, err := r.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}

	decrypted, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key, stanzas[0].Body, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(fileKey) {
		t.Error("decrypted key does not match original")
	}
}

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
