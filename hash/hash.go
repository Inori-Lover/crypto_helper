package hash

import (
	"crypto/sha512"

	"golang.org/x/crypto/blake2b"
)

type hash struct{}

// main export
var Hash = hash{}

func (c *hash) Default(plaintext []byte) (hashBytes []byte) {
	return c.BLAKE_2(plaintext)
}

// i faster than md5 but as secure as sha2, forget md5 please
func (c *hash) BLAKE_2(plaintext []byte) (hashBytes []byte) {
	// why 256: because aes max is 256
	s := blake2b.Sum256(plaintext)
	return s[:]
}

func (c *hash) SHA_2(plaintext []byte) (hashBytes []byte) {
	s := sha512.Sum512_256(plaintext)
	return s[:]
}
