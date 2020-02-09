package hash

import (
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
)

// Blake2 i faster than md5 but as secure as sha2, forget md5 please
func Blake2(plaintext []byte) (hashBytes []byte) {
	// why 256: because aes max is 256
	s := blake2b.Sum256(plaintext)
	return s[:]
}

// Sha2 ...
func Sha2(plaintext []byte) (hashBytes []byte) {
	s := sha512.Sum512_256(plaintext)
	return s[:]
}
