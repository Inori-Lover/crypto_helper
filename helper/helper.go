package helper

import (
	"bytes"
)

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

var ErrorCBHub = []func(err error){}

func AddErrorCB(cb func(err error)) {
	ErrorCBHub = append(ErrorCBHub, cb)
}

func PublishError(err error) {
	for _, cb := range ErrorCBHub {
		go func(cb func(err error)) {
			cb(err)
		}(cb)
	}
}
