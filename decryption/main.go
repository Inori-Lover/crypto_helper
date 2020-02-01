package decryption

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto_helper/helper"
)

// Default is AES_CTR_256
func Default(ciphertext []byte, key [32]byte) []byte {
	return AES_CTR_256(ciphertext, key)
}