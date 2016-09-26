package main

import (
	"fmt"
	"github.com/Rudd-O/curvetls"
	"log"
)

func main() {
	pr, pu, err := curvetls.GenKeyPair()
	if err != nil {
		log.Fatalf("Could not generate keypair: %s", err)
	}
	fmt.Printf("Private key: %s\n", pr)
	fmt.Printf("Public key:  %s\n", pu)
	fmt.Println("Tip:         Both keys are encoded in base64 format with a one-character key type prefix")
}
