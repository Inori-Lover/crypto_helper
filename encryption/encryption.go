package encryption

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto_helper/hash"
	"crypto_helper/helper"
)

type encryption struct{}

// main export
var Encryption = encryption{}

// Default is AES_CTR_256
func (c *encryption) Default(plaintext []byte, key [32]byte) []byte {
	return c.AES_CTR_256(plaintext, key)
}

func (c *encryption) aesCBC(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	plaintext = helper.PKCS7Padding(plaintext, blockSize)
	iv := hash.Hash.BLAKE_2(plaintext)[:blockSize]

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, plaintext)

	return append(iv, ciphertext...)
}

func (c *encryption) AES_CBC_128(plaintext []byte, key [16]byte) []byte {
	return c.aesCBC(plaintext, key[:])
}
func (c *encryption) AES_CBC_192(plaintext []byte, key [24]byte) []byte {
	return c.aesCBC(plaintext, key[:])
}
func (c *encryption) AES_CBC_256(plaintext []byte, key [32]byte) []byte {
	return c.aesCBC(plaintext, key[:])
}

func (c *encryption) aesCTR(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := hash.Hash.BLAKE_2(plaintext)[:blockSize]

	ciphertext := make([]byte, len(plaintext))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertext, plaintext)

	return append(iv, ciphertext...)
}
func (c *encryption) AES_CTR_128(plaintext []byte, key [16]byte) []byte {
	return c.aesCTR(plaintext, key[:])
}
func (c *encryption) AES_CTR_192(plaintext []byte, key [24]byte) []byte {
	return c.aesCTR(plaintext, key[:])
}
func (c *encryption) AES_CTR_256(plaintext []byte, key [32]byte) []byte {
	return c.aesCTR(plaintext, key[:])
}

func (c *encryption) aesGCM(plaintext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	// AES_GCM 的 最佳iv长度 永远是 12
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv := hash.Hash.BLAKE_2(plaintext)[:12]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}
	ciphertext := aesgcm.Seal(nil, iv, plaintext, nil)

	return append(iv, ciphertext...)
}
func (c *encryption) AES_GCM_128(plaintext []byte, key [16]byte) []byte {
	return c.aesGCM(plaintext, key[:])
}
func (c *encryption) AES_GCM_192(plaintext []byte, key [24]byte) []byte {
	return c.aesGCM(plaintext, key[:])
}
func (c *encryption) AES_GCM_256(plaintext []byte, key [32]byte) []byte {
	return c.aesGCM(plaintext, key[:])
}
