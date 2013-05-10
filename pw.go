/*
Copyright Mike Hughes 2012 (intermernet AT gmail DOT com)

pw is a Go library for password authentication

It attempts to put into practice the methodology described in CrackStation's "Salted Password
Hashing - Doing it Right". [1]

It uses scrypt for key stretching, and assumes the use of an HMAC key for extra security.

The HMAC key should be provided from somewhere outside of the database which stores the user IDs,
hashes and salts. It should, at least, be stored in a secure file on the server, but it's
recommended to use an external server, or service, to provide the HMAC key.

The generated hashes are 256 bits in length, as are any generated salts.

The input HMAC key and password are only limited in length by the underlying Go crypto libraries.

The library provides 2 functions:

Check:
- Takes an HMAC key, a hash to verify, a password and a salt (as byte slices)
- scrypt transforms the password and salt, and then HMAC transforms the result.
- Compares the resulting 256 bit HMAC hash against the input hash.
- Returns a boolean.

New:
- Takes an HMAC key and a password (as byte slices)
- Generates a new salt using "crypto/rand"
- scrypt transforms the password and salt, and then HMAC transforms the result.
- Returns the resulting 256 bit HMAC hash and the 256 bit salt.

[1] http://crackstation.net/hashing-security.htm
*/

package pw

import (
	"code.google.com/p/go.crypto/scrypt"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
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

// pwHash contains the HMAC, the password, the salt, and the final hash
type PwHash struct {
	Hmac []byte
	Pass string
	Salt []byte
	Hash []byte
}

// New returns a new pwHash
func New() *PwHash { return new(pwHash) }

// doHash scrypt transforms the password and salt, and then HMAC transforms the result.
// Returns the resulting 256 bit hash.
func (p *pwHash) doHash() (h []byte, err error) {
	sck, err := scrypt.Key([]byte(p.Pass), p.Salt, N, R, P, KEYLENGTH)
	if err != nil {
		return nil, err
	}
	hmh := hmac.New(sha256.New, p.Hmac)
	hmh.Write(sck)
	p.Hash = hmh.Sum(nil)
	return p.Hash, nil
}

// Check call doHash() and compares the resulting hash against the check hash and returns a boolean.
func (p *PwHash) Check() (chk bool, err error) {
	hchk, err := p.doHash()
	if err != nil {
		return false, err
	}
	if subtle.ConstantTimeCompare(p.Hash, hchk) != 1 {
		return false, errors.New("Error: Hash verification failed")
	}
	return true, nil
}

// New generates a new salt using "crypto/rand"
// It then calls doHash() and returns the resulting hash and salt.
func (p *PwHash) New() (err error) {
	p.Salt = make([]byte, KEYLENGTH)
	_, err = io.ReadFull(rand.Reader, p.Salt)
	if err != nil {
		return err
	}
	p.Hash, err = p.doHash()
	if err != nil {
		return err
	}
	return nil
}
