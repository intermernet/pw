[![GoDoc](https://godoc.org/github.com/Intermernet/pw?status.png)](https://godoc.org/github.com/Intermernet/pw) [![Build Status](https://drone.io/github.com/Intermernet/pw/status.png)](https://drone.io/github.com/Intermernet/pw/latest) [![Coverage Status](https://coveralls.io/repos/Intermernet/pw/badge.png?branch=master)](https://coveralls.io/r/Intermernet/pw?branch=master)

pw is a Go library for password authentication

[![Build Status](https://drone.io/github.com/Intermernet/pw/status.png)](https://drone.io/github.com/Intermernet/pw/latest)

It attempts to put into practice the methodology described in [CrackStation's "Salted Password
Hashing - Doing it Right".][1]

It uses scrypt for key stretching, and assumes the use of an HMAC key for extra security.

The HMAC Key should be provided from somewhere outside of the database which stores the user IDs,
hashes and salts. It should, at least, be stored in a secure file on the server, but it's 
recommended to use an external server, or service, to provide the HMAC key.

The generated hashes are 256 bits in length, as are any generated salts.

The input HMAC key and password are only limited in length by the underlying Go crypto libraries.

Documentation available at http://godoc.org/github.com/Intermernet/pw

[1]: http://crackstation.net/hashing-security.htm