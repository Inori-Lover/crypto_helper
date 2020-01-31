package decryption

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto_helper/helper"
)

type decryption struct{}

// main export
var Decryption = decryption{}

// Default is AES_CTR_256
func (c *decryption) Default(ciphertext []byte, key [32]byte) []byte {
	return c.AES_CTR_256(ciphertext, key)
}

func (c *decryption) aesCBC(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)

	// 如果两个参数是同一变量的话解密会“原地进行”
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	plaintext := helper.PKCS7UnPadding(ciphertext)

	return plaintext
}

func (c *decryption) AES_CBC_128(ciphertext []byte, key [16]byte) []byte {
	return c.aesCBC(ciphertext, key[:])
}
func (c *decryption) AES_CBC_192(ciphertext []byte, key [24]byte) []byte {
	return c.aesCBC(ciphertext, key[:])
}
func (c *decryption) AES_CBC_256(ciphertext []byte, key [32]byte) []byte {
	return c.aesCBC(ciphertext, key[:])
}

func (c *decryption) aesCTR(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	blockSize := block.BlockSize()

	iv := ciphertext[:blockSize]
	ciphertext = ciphertext[blockSize:]

	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(plaintext, ciphertext)

	return plaintext
}

func (c *decryption) AES_CTR_128(ciphertext []byte, key [16]byte) []byte {
	return c.aesCTR(ciphertext, key[:])
}
func (c *decryption) AES_CTR_192(ciphertext []byte, key [24]byte) []byte {
	return c.aesCTR(ciphertext, key[:])
}
func (c *decryption) AES_CTR_256(ciphertext []byte, key [32]byte) []byte {
	return c.aesCTR(ciphertext, key[:])
}

func (c *decryption) aesGCM(ciphertext []byte, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	// AES_GCM 的 最佳iv长度 永远是 12
	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	iv := ciphertext[:12]
	ciphertext = ciphertext[12:]

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	plaintext, err := aesgcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		helper.PublishError(err)
		return []byte{}
	}

	return plaintext
}

func (c *decryption) AES_GCM_128(ciphertext []byte, key [16]byte) []byte {
	return c.aesGCM(ciphertext, key[:])
}
func (c *decryption) AES_GCM_192(ciphertext []byte, key [24]byte) []byte {
	return c.aesGCM(ciphertext, key[:])
}
func (c *decryption) AES_GCM_256(ciphertext []byte, key [32]byte) []byte {
	return c.aesGCM(ciphertext, key[:])
}
