package cryptor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func testKey() string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
}

func TestEncryptDecryptWithAdditionalData(t *testing.T) {
	c, err := New(testKey())
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := c.Encrypt([]byte("Bearer segreto"), []byte("events"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("segreto")) {
		t.Fatal("the ciphertext contains the plaintext")
	}
	plaintext, err := c.Decrypt(ciphertext, []byte("events"))
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "Bearer segreto" {
		t.Fatalf("plaintext = %q", plaintext)
	}
}

func TestDecryptRejectsDifferentSubject(t *testing.T) {
	c, _ := New(testKey())
	ciphertext, _ := c.Encrypt([]byte("body"), []byte("events"))
	if _, err := c.Decrypt(ciphertext, []byte("logs")); err == nil {
		t.Fatal("Decrypt() did not reject different additional data")
	}
}

func TestNewRejectsInvalidKey(t *testing.T) {
	if _, err := New(base64.StdEncoding.EncodeToString([]byte("short"))); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("New() error = %v, want ErrInvalidKey", err)
	}
}
