package main

import (
	"fmt"
)

// 为什么创建这个库
// 1. 原生的加密函数错误处理导致导致不能实现行内赋值
// 2. IV的选取策略令人迷惑，并非所有人都知道IV的目的是什么
// 3. 并没有人简单知道自己可以选什么类型的加密、hash等

func main() {
	fmt.Println(Encryption.Default([]byte(""), []byte("")))
}
