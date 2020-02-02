package helper

import (
	"bytes"
)

// PKCS7Padding PKCS#7 padding
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding PKCS#7 unpadding
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// ErrorCBHub 错误监听
var ErrorCBHub = []func(err error){}

// AddErrorCB 添加错误监听回调
func AddErrorCB(cb func(err error)) {
	ErrorCBHub = append(ErrorCBHub, cb)
}

// PublishError 发布错误信息
func PublishError(err error) {
	for _, cb := range ErrorCBHub {
		go func(cb func(err error)) {
			cb(err)
		}(cb)
	}
}
