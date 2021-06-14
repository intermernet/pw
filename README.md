[![PkgGoDev](https://pkg.go.dev/badge/github.com/intermernet/pw)](https://pkg.go.dev/github.com/intermernet/pw)

pw is a Go library for password authentication

It attempts to put into practice the methodology described in [CrackStation's "Salted Password
Hashing - Doing it Right".][1]

It uses [scrypt][2] for key derivation, and assumes the use of an HMAC key for extra security.

The HMAC Key should be provided from somewhere outside of the database which stores the user IDs,
hashes and salts. It should, at least, be stored in a secure file on the server, but it's
recommended to use an external server, or service, to provide the HMAC key.

The generated hashes are 256 bits in length, as are any generated salts.

The input HMAC key and password are only limited in length by the underlying Go crypto libraries.

Documentation available at https://pkg.go.dev/github.com/intermernet/pw

[1]: http://crackstation.net/hashing-security.htm
[2]: http://www.tarsnap.com/scrypt.html
