package utils

import (
	"fmt"
	"log"
)

func PanicError(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func PrintDump(dumpChan chan string) {
	str := <-dumpChan
	up := "\x1b[2F"
	fmt.Print(up)
	fmt.Print(str)
}
