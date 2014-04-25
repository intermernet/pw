/*
Copyright Mike Hughes 2013 (intermernet AT gmail DOT com)

pw is a Go library for password authentication

It attempts to put into practice the methodology described in CrackStation's "Salted Password
Hashing - Doing it Right". [1]

It uses the scrypt KDF for key stretching, and assumes the use of an HMAC key for extra security.

The HMAC key should be provided from somewhere outside of the database which stores the user IDs,
hashes and salts. It should, at least, be stored in a secure file on the server, but it's
recommended to use an external server, or service, to provide the HMAC key.

The generated hashes are 256 bits in length, as are any generated salts.

The input HMAC key and password are only limited in length by the underlying Go crypto libraries.

Use godoc [2] for documentation

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

	"code.google.com/p/go.crypto/scrypt"
)

const (
	// Key length and salt length will be 32 bytes (256 bits)
	KEYLENGTH = 32

	// "N is a CPU/memory cost parameter, which must be a power of two greater than 1.
	// r and p must satisfy r * p < 2³⁰. If the parameters do not satisfy the
	// limits, the function returns a nil byte slice and an error."
	// From http://code.google.com/p/go/source/browse/scrypt/scrypt.go?repo=crypto
	N = 16384
	R = 8
	P = 1
)

// pwHash contains the HMAC, the password, the salt and the hash to check
type PwHash struct {
	Hmac []byte // HMAC Key
	Pass string // Password
	Salt []byte // Salt
	Hash []byte // Hash to check
	hchk []byte // Hash to check against
}

// New returns a new pwHash
func New() *PwHash { return new(PwHash) }

// doHash scrypt transforms the password and salt, and then HMAC transforms the result.
// and sets it as the check-hash.
func (ph *PwHash) doHash() error {
	sck, err := scrypt.Key([]byte(ph.Pass), ph.Salt, N, R, P, KEYLENGTH)
	if err != nil {
		return err
	}
	hmh := hmac.New(sha256.New, ph.Hmac)
	defer hmh.Reset()
	hmh.Write(sck)
	ph.hchk = hmh.Sum(nil)
	return nil
}

// randSalt generates a random slice of bytes using crypto/rand
// of length KEYLENGTH and sets it as the salt.
func (ph *PwHash) randSalt() error {
	rh := make([]byte, KEYLENGTH)
	defer func() { rh = []byte{} }() // Clear the salt
	if _, err := rand.Read(rh); err != nil {
		return err
	}
	ph.Salt = rh
	return nil
}

// Create generates a new salt using "crypto/rand"
// It then calls doHash() and sets the resulting hash and salt.
func (ph *PwHash) Create() error {
	defer func() { ph.Hash, ph.hchk = ph.hchk, []byte{} }() // Clear the hchk field.
	if err := ph.randSalt(); err != nil {
		return err
	}
	if err := ph.doHash(); err != nil {
		return err
	}
	return nil
}

// Check calls doHash() and compares the resulting hash against the check hash.
// Returns a boolean.
func (ph *PwHash) Check() (bool, error) {
	defer func() { ph.Hash, ph.hchk = []byte{}, []byte{} }() // Clear the Hash and hchk fields.
	chkerr := errors.New("hash verification failed")
	if err := ph.doHash(); err != nil {
		return false, err
	}
	if subtle.ConstantTimeEq(int32(len(ph.Hash)), int32(len(ph.hchk))) == 1 {
		if subtle.ConstantTimeCompare(ph.hchk, ph.Hash) == 1 {
			return true, nil
		}
	}
	return false, chkerr
}
