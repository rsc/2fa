// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	"filippo.io/age"
)

// KeyExport represents an exported 2FA key
type KeyExport struct {
	Name    string `json:"name"`
	Digits  int    `json:"digits"`
	Key     string `json:"key"`
	Type    string `json:"type"` // "totp" or "hotp"
	Counter uint64 `json:"counter,omitempty"`
}

// exportKey exports a single key encrypted with age
func (c *Keychain) exportKey(name string, recipients []string, output io.Writer) error {
	k, ok := c.keys[name]
	if !ok {
		return fmt.Errorf("no such key %q", name)
	}

	// Parse age recipients
	var ageRecipients []age.Recipient
	for _, r := range recipients {
		recipient, err := age.ParseX25519Recipient(r)
		if err != nil {
			return fmt.Errorf("invalid age recipient %q: %v", r, err)
		}
		ageRecipients = append(ageRecipients, recipient)
	}

	// Create export structure
	export := KeyExport{
		Name:   name,
		Digits: k.digits,
		Key:    encodeKey(k.raw),
		Type:   "totp",
	}

	// Check if it's HOTP (has counter)
	if k.offset != 0 {
		// Read current counter
		counter := string(c.data[k.offset : k.offset+counterLen])
		fmt.Sscanf(counter, "%d", &export.Counter)
		export.Type = "hotp"
	}

	// Marshal to JSON
	plaintext, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling export: %v", err)
	}

	// Encrypt with age
	w, err := age.Encrypt(output, ageRecipients...)
	if err != nil {
		return fmt.Errorf("creating age encryptor: %v", err)
	}

	if _, err := w.Write(plaintext); err != nil {
		return fmt.Errorf("encrypting data: %v", err)
	}

	if err := w.Close(); err != nil {
		return fmt.Errorf("closing encryptor: %v", err)
	}

	return nil
}

// importKey imports an age-encrypted key
func (c *Keychain) importKey(input io.Reader, identityPaths []string) error {
	// Parse age identities
	var identities []age.Identity
	for _, path := range identityPaths {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("opening identity file %q: %v", path, err)
		}
		defer f.Close()

		ids, err := age.ParseIdentities(f)
		if err != nil {
			return fmt.Errorf("parsing identity file %q: %v", path, err)
		}
		identities = append(identities, ids...)
	}

	if len(identities) == 0 {
		return fmt.Errorf("no identities provided")
	}

	// Decrypt with age
	r, err := age.Decrypt(input, identities...)
	if err != nil {
		return fmt.Errorf("decrypting data: %v", err)
	}

	// Read plaintext
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return fmt.Errorf("reading decrypted data: %v", err)
	}

	// Unmarshal JSON
	var export KeyExport
	if err := json.Unmarshal(buf.Bytes(), &export); err != nil {
		return fmt.Errorf("parsing export: %v", err)
	}

	// Validate key
	_, err = decodeKey(export.Key)
	if err != nil {
		return fmt.Errorf("invalid key in export: %v", err)
	}

	// Check if key already exists
	if _, exists := c.keys[export.Name]; exists {
		return fmt.Errorf("key %q already exists in keychain", export.Name)
	}

	// Format key line
	line := fmt.Sprintf("%s %d %s", export.Name, export.Digits, export.Key)
	if export.Type == "hotp" {
		line += " " + fmt.Sprintf("%020d", export.Counter)
	}
	line += "\n"

	// Append to keychain file
	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("opening keychain: %v", err)
	}
	defer f.Close()

	f.Chmod(0600)

	if _, err := f.Write([]byte(line)); err != nil {
		return fmt.Errorf("writing key: %v", err)
	}

	log.Printf("imported key %q (%s, %d digits)", export.Name, export.Type, export.Digits)

	return nil
}

// encodeKey encodes raw bytes back to base32
func encodeKey(raw []byte) string {
	return base32.StdEncoding.EncodeToString(raw)
}

// generateAgeIdentity generates a new age identity and prints it
func generateAgeIdentity() error {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return fmt.Errorf("generating identity: %v", err)
	}

	// Print identity file format (matches age-keygen output)
	fmt.Printf("# created: %s\n", os.Getenv("USER"))
	fmt.Printf("# public key: %s\n", identity.Recipient())
	fmt.Printf("%s\n", identity)

	// Print instructions to stderr so they don't interfere with piping
	log.Printf("")
	log.Printf("✓ Age identity generated")
	log.Printf("")
	log.Printf("Save to file:       ./2fa -keygen > ~/.age/key.txt && chmod 600 ~/.age/key.txt")
	log.Printf("Your public key:    %s", identity.Recipient())
	log.Printf("")

	return nil
}
