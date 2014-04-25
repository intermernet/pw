/*
Copyright Mike Hughes 2013 (intermernet AT gmail DOT com)

pw is a Go library for password authentication

It attempts to put into practice the methodology described in CrackStation's "Salted Password
Hashing - Doing it Right". [1]

It uses scrypt for key stretching, and assumes the use of an HMAC key for extra security.

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
	"io"

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
// Returns the resulting 256 bit hash.
func (p *PwHash) doHash() error {
	sck, err := scrypt.Key([]byte(p.Pass), p.Salt, N, R, P, KEYLENGTH)
	if err != nil {
		return err
	}
	hmh := hmac.New(sha256.New, p.Hmac)
	defer hmh.Reset()
	hmh.Write(sck)
	p.hchk = hmh.Sum(nil)
	return nil
}

// randSalt generates a random slice of bytes using crypto/rand
// of length KEYLENGTH and sets it as the salt
func (p *PwHash) randSalt() error {
	rh := make([]byte, KEYLENGTH)
	defer func() { rh = []byte{} }()
	if _, err := io.ReadFull(rand.Reader, rh); err != nil {
		return err
	}
	p.Salt = rh
	return nil
}

// Create generates a new salt using "crypto/rand"
// It then calls doHash() and sets the resulting hash and salt.
func (p *PwHash) Create() error {
	if err := p.randSalt(); err != nil {
		return err
	}
	if err := p.doHash(); err != nil {
		return err
	}
	p.Hash, p.hchk = p.hchk, []byte{} // Clear the hchk field.
	return nil
}

// Check calls doHash() and compares the resulting hash against the check hash.
// Returns a boolean.
func (p *PwHash) Check() (bool, error) {
	chkerr := errors.New("Error: Hash verification failed")
	if err := p.doHash(); err != nil {
		return false, err
	}
	if subtle.ConstantTimeEq(int32(len(p.Hash)), int32(len(p.hchk))) != 1 {
		return false, chkerr
	}
	if subtle.ConstantTimeCompare(p.hchk, p.Hash) != 1 {
		return false, chkerr
	}
	p.Hash, p.hchk = []byte{}, []byte{} // Clear the Hash and hchk fields.
	return true, nil
}
