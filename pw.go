/*
Package pw is a Go library for password authentication.

It attempts to put into practice the methodology described in CrackStation's "Salted Password
Hashing - Doing it Right". [1]

It uses the scrypt KDF for key stretching, and assumes the use of an HMAC key for extra security.

The HMAC key should be provided from somewhere outside of the database which stores the user IDs,
hashes and salts. It should, at least, be stored in a secure file on the server, but it's
recommended to use an external server, or service, to provide the HMAC key.

The generated hashes are 256 bits in length, as are any generated salts.

The input HMAC key and password are only limited in length by the underlying Go crypto libraries.

Use godoc [2] for documentation.

Copyright Mike Hughes 2013 (intermernet AT gmail DOT com).

[1] http://crackstation.net/hashing-security.htm

[2] http://godoc.org/github.com/Intermernet/pw
*/
package pw

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"

	"code.google.com/p/go.crypto/scrypt"
)

const (
	// Key length and salt length will be 32 bytes (256 bits)
	keyLength = 32

	// scrypt constants from http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto
	// "N is a CPU/memory cost parameter, which must be a power of two greater than 1.
	// r and p must satisfy r * p < 2³⁰. If the parameters do not satisfy the
	// limits, the function returns a nil byte slice and an error."
	n = 16384
	r = 8
	p = 1
)

// ID contains the HMAC, the password, the salt and the hash to check.
type ID struct {
	Hmac []byte // HMAC Key
	Pass string // Password
	Salt []byte // Salt
	Hash []byte // Hash to check
	hchk []byte // Hash to compare against
}

// New returns a new ID.
func New() *ID { return new(ID) }

// doHash scrypt transforms the password and salt, and then HMAC transforms the result.
// Assigns the resulting hash to the comparison hash.
func (i *ID) doHash() error {
	sck, err := scrypt.Key([]byte(i.Pass), i.Salt, n, r, p, keyLength)
	if err != nil {
		return err
	}
	hmh := hmac.New(sha256.New, i.Hmac)
	hmh.Write(sck)
	i.hchk = hmh.Sum(nil)
	return nil
}

// randSalt generates a random slice of bytes using crypto/rand
// of length keyLength and assigns it as a new salt.
func (i *ID) randSalt() error {
	rh := make([]byte, keyLength)
	if _, err := io.ReadFull(rand.Reader, rh); err != nil {
		return err
	}
	i.Salt = rh
	return nil
}

// Create generates a new salt using "crypto/rand".
// It then calls doHash() and sets the resulting hash and salt.
func (i *ID) Create() error {
	defer func() { i.Hash, i.hchk = i.hchk, []byte{} }() // Clear the hchk field.
	if err := i.randSalt(); err != nil {
		return err
	}
	if err := i.doHash(); err != nil {
		return err
	}
	return nil
}

// Check calls doHash() and compares the resulting hash against the check hash.
// Returns a boolean.
func (i *ID) Check() (bool, error) {
	defer func() { i.Hash, i.hchk = []byte{}, []byte{} }() // Clear the Hash and hchk fields.
	chkErr := errors.New("hash verification failed")
	if err := i.doHash(); err != nil {
		return false, err
	}
	if subtle.ConstantTimeEq(int32(len(i.Hash)), int32(len(i.hchk))) == 1 {
		if subtle.ConstantTimeCompare(i.hchk, i.Hash) == 1 {
			return true, nil
		}
	}
	return false, chkErr
}
