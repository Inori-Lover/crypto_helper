package hash

import (
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
)

func Default(plaintext []byte) (hashBytes []byte) {
	return BLAKE_2(plaintext)
}

// i faster than md5 but as secure as sha2, forget md5 please
func BLAKE_2(plaintext []byte) (hashBytes []byte) {
	// why 256: because aes max is 256
	s := blake2b.Sum256(plaintext)
	return s[:]
}

func SHA_2(plaintext []byte) (hashBytes []byte) {
	s := sha512.Sum512_256(plaintext)
	return s[:]
}
