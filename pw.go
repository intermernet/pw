// Package pw is a Go library for password authentication.
//
// It attempts to put into practice the methodology described in CrackStation's "Salted Password
// Hashing - Doing it Right". [1]
//
// It uses the scrypt KDF for key derivation, and assumes the use of an HMAC key for extra security.
//
// The HMAC key should be provided from somewhere outside of the database which stores the user IDs,
// hashes and salts. It should, at least, be stored in a secure file on the server, but it's
// recommended to use an external server, or service, to provide the HMAC key.
//
// The generated hashes are 256 bits in length, as are any generated salts.
//
// The input HMAC key and password are only limited in length by the underlying Go crypto libraries.
//
// Use godoc [2] for documentation.
//
// Copyright Mike Hughes 2012 - 2015 (intermernet AT gmail DOT com).
//
// [1] http://crackstation.net/hashing-security.htm
//
// [2] http://godoc.org/github.com/Intermernet/pw
package pw

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"

	"golang.org/x/crypto/scrypt"
)

const (
	// KeyLen (key length and salt length) is 32 bytes (256 bits)
	KeyLen = 32

	// N is a CPU/memory cost parameter
	N = 16384
	// R must satisfy R * P < 2³⁰.
	R = 8
	// P must satisfy R * P < 2³⁰.
	P = 1
)

var (
	randSrc    = rand.Reader
	errVerFail = errors.New("verification failed")
)

// ID contains the HMAC, the password, the salt and the hash to check.
//
// Description of scrypt variables from https://golang.org/x/crypto/scrypt
//
// "N is a CPU/memory cost parameter, which must be a power of two greater than 1.
// R and P must satisfy R * P < 2³⁰."
//
// These were valid @ 2009 and should be increased as CPU power increases.
// Please see http://www.tarsnap.com/scrypt.html for details.
//
// Defaults are  N = 16384, R = 8, P = 1
type ID struct {
	Pass    string // Password
	Hmac    []byte // HMAC Key
	Salt    []byte // Salt
	Hash    []byte // Hash to check
	N, R, P int    // scrypt variables

	hchk []byte // Hash to compare against
}

// New returns a new ID.
func New() *ID {
	return &ID{
		N: N,
		R: R,
		P: P,
	}
}

// doHash scrypt transforms the password and salt, and then HMAC transforms the result.
// Assigns the resulting hash to the comparison hash.
func (i *ID) doHash() error {
	sck, err := scrypt.Key([]byte(i.Pass), i.Salt, i.N, i.R, i.P, KeyLen)
	if err != nil {
		return err
	}
	hmh := hmac.New(sha256.New, i.Hmac)
	hmh.Write(sck)
	i.hchk = hmh.Sum(nil)
	return nil
}

// randSalt generates a random slice of bytes using crypto/rand
// of length KeyLen and assigns it as a new salt.
func (i *ID) randSalt() error {
	rh := make([]byte, KeyLen)
	if _, err := io.ReadFull(randSrc, rh); err != nil {
		return err
	}
	i.Salt = rh
	return nil
}

// Set Initializes an ID with a password and an HMAC.
//
// It generates a new salt using "crypto/rand"
// and then sets the resulting hash and salt.
func (i *ID) Set() error {
	defer func() { i.Hash, i.hchk = i.hchk, []byte{} }() // Set Hash, clear hchk
	if err := i.randSalt(); err != nil {
		return err
	}
	if err := i.doHash(); err != nil {
		return err
	}
	return nil
}

// Check compares the supplied hash against the check hash and
// returns a boolean.
func (i *ID) Check() (bool, error) {
	defer func() { i.Hash, i.hchk = []byte{}, []byte{} }() // Clear Hash and hchk
	if err := i.doHash(); err != nil {
		return false, err
	}
	if subtle.ConstantTimeEq(int32(len(i.Hash)), int32(KeyLen)) == 1 {
		if subtle.ConstantTimeCompare(i.hchk, i.Hash) == 1 {
			return true, nil
		}
	}
	return false, errVerFail
}
