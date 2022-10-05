package main

import (
	"fmt"
	"os"
)

func main() {
	if os.Args[1] == "sshgencert" {
		fmt.Println(os.Args[3] + " " + os.Args[2])
	}
}
