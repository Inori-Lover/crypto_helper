package main

import (
	"bytes"
	"fmt"

	"crypto_helper/decryption"
	"crypto_helper/encryption"
	"crypto_helper/helper"
)

// 为什么创建这个库
// 1. 原生的加密函数错误处理导致导致不能实现行内赋值
// 2. IV的选取策略令人迷惑，并非所有人都知道IV的目的是什么
// 3. 并没有人简单知道自己可以选什么类型的加密、hash等

func AddErrorCB(cb func(err error)) {
	helper.AddErrorCB(cb)
}

func main() {
	AddErrorCB(func(err error) {
		fmt.Println("crypto.helper err:", err)
	})

	plaintext := []byte("hello")
	key := [32]byte{12, 34, 123, 13, 3, 4, 5, 6, 63, 7, 8, 88}

	fmt.Println("begin")
	fmt.Println("============= 原文")
	fmt.Println(plaintext)
	fmt.Println("============= key")
	fmt.Println(key)
	fmt.Println("============= 加密")
	ciphertext := encryption.Default(plaintext, key)
	fmt.Println(ciphertext)
	fmt.Println("============= 解密")
	fmt.Println(decryption.Default(ciphertext, key))
	fmt.Println("============= 加密 == 解密")
	fmt.Println(bytes.Equal(plaintext, decryption.Default(ciphertext, key)))
}
