package main

import (
	"fmt"
	"os"

	"github.com/ZeroPvlse/razor/mess"
)

func main() {

	if len(os.Args) > 2 {
		fmt.Println("too many agrs: usage razor-gen [name]")
		os.Exit(1)
	}

	if len(os.Args) < 2 {
		fmt.Println("too little arguments: usage razor-gen [name]")
		os.Exit(2)
	}

	mess.PrintAscii(mess.GenLogo)
	mess.GenerateTemplate(os.Args[1])

}
