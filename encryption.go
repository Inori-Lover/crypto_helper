package main

import (
	"crypto/aes"
	"crypto/cipher"

	"crypto.helper/helper"
)

type encryption struct{}

// main export
var Encryption encryption

func (c *encryption) Default(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return c.AES_CTR_128(plaintext, key)
}

func (c *encryption) AES_CBC_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	block, err := aes.NewCipher(key)
	if err != nil {
		helper.PublishError(err)
		return ciphertext, iv
	}
	blockSize := block.BlockSize()
	origData = PKCS5Padding(origData, blockSize)
	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

func (c *encryption) AES_CBC_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *encryption) AES_CTR_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *encryption) AES_CTR_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *encryption) AES_GCM_128(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}

func (c *encryption) AES_GCM_256(plaintext []byte, key []byte) (ciphertext []byte, iv []byte) {
	return ciphertext, iv
}
