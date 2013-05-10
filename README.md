pw is a Go library for password authentication

It attempts to put into practice the methodology described in [CrackStation's "Salted Password
Hashing - Doing it Right".][1]

It uses scrypt for key stretching, and assumes the use of an HMAC key for extra security.

The HMAC Key should be provided from somewhere outside of the database which stores the user IDs,
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
- Takes an HMAC Key and a Password (as byte slices)
- Generates a new Salt using "crypto/rand"
- scrypt transforms the password and salt, and then HMAC transforms the result.
- Returns the resulting 256 bit HMAC hash and the 256 bit Salt.

[1]: http://crackstation.net/hashing-security.htm