// Package pw is a Go library for password authentication.
//
// It attempts to put into practice the methodology described in CrackStation's
// "Salted Password Hashing - Doing it Right". [1]
//
// It uses the scrypt KDF for key derivation, and assumes the use of an HMAC key
// for extra security.
//
// The HMAC key should be provided from somewhere outside of the database which
// stores the user IDs, hashes and salts. It should, at least, be stored in a
// secure file on the server, but it's recommended to use an external server, or
// service, to provide the HMAC key.
//
// The generated hashes are 256 bits in length, as are any generated salts.
//
// The input HMAC key and password are only limited in length by the underlying
// Go crypto libraries.
//
// Use https://pkg.go.dev/ [2] for documentation.
//
// Copyright Mike Hughes 2012 - 2021 (mike AT mikehughes DOT info).
//
// [1] http://crackstation.net/hashing-security.htm
//
// [2] https://pkg.go.dev/github.com/intermernet/pw
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
	N = 32768
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
// It's possible to tune the scrypt variables (N, R and P), but changing these
// will require recreation of all previous hashes.
//
// Description of scrypt variables from https://golang.org/x/crypto/scrypt:
// "N is a CPU/memory cost parameter, which must be a power of two greater than
// 1. R and P must satisfy R * P < 2³⁰."
//
// The following quote is from http://www.tarsnap.com/scrypt/scrypt.pdf
// May 2009.
//
// "Users of scrypt can tune the parameters N, r, and p according to the amount
// of memory and computing power available, the latency-bandwidth product of the
// memory subsystem, and the amount of parallelism desired; at the current time,
// taking r = 8 and p = 1 appears to yield good results, but as memory latency
// and CPU parallelism increase it is likely that the optimum values for both r
// and p will increase"
//
// Defaults are  N = 16384, R = 8, P = 1
//
// As of 2020 N is now 32768
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

// doHash scrypt transforms the password and salt, and then HMAC transforms the
// result. It assigns the resulting hash to the comparison hash.
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
//
// Users should store ID.Hash and ID.Salt, and ensure that ID.Hmac is stored
// in a separate location (This is best practice, but not required for some
// purposes. You can leave ID.Hmac empty but you will lose some security).
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

// Verify returns true if the supplied ID.Pass, ID.Hmac and ID.Hash are valid.
func (i *ID) Verify() (bool, error) {
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
