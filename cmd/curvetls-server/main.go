package main

import (
	"github.com/Rudd-O/curvetls"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 4 || len(os.Args) > 5 {
		log.Fatalf("usage: curvetls-server <IP:port> <server privkey> <server pubkey> [client pubkey]")
	}

	bind := os.Args[1]
	serverPrivkey, err := curvetls.PrivkeyFromString(os.Args[2])
	if err != nil {
		log.Fatalf("Server: failed to parse server private key: %s", err)
	}
	serverPubkey, err := curvetls.PubkeyFromString(os.Args[3])
	if err != nil {
		log.Fatalf("Server: failed to parse server public key: %s", err)
	}
	var noPubkey curvetls.Pubkey
	var clientPubkey curvetls.Pubkey
	if len(os.Args) == 5 {
		clientPubkey, err = curvetls.PubkeyFromString(os.Args[4])
		if err != nil {
			log.Fatalf("Server: failed to parse client public key: %s", err)
		}
	} else {
		clientPubkey = noPubkey
	}

	listener, err := net.Listen("tcp4", bind)
	if err != nil {
		log.Fatalf("Server: could not run server: %s", err)
	}

	socket, err := listener.Accept()
	if err != nil {
		log.Fatalf("Server: failed to accept socket: %s", err)
	}

	long_nonce, err := curvetls.NewLongNonce()
	if err != nil {
		log.Fatalf("Server: failed to generate nonce: %s", err)
	}
	ssocket, clientpubkey, err := curvetls.WrapServer(socket, serverPrivkey, serverPubkey, long_nonce)
	if err != nil {
		log.Fatalf("Server: failed to wrap socket: %s", err)
	}
	log.Printf("Server: client's public key is %s", clientpubkey)

	var allowed bool
	if clientPubkey == noPubkey {
		err = ssocket.Allow()
		allowed = true
	} else if clientPubkey == clientpubkey {
		err = ssocket.Allow()
		allowed = true
	} else {
		err = ssocket.Deny()
		allowed = false
	}

	if err != nil {
		log.Fatalf("Server: failed to process authorization: %s", err)
	}

	if allowed {
		var packet [8]byte
		var smallPacket [8]byte

		_, err = ssocket.Read(packet[:])
		if err != nil {
			log.Fatalf("Server: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Server: the first received packet is %s", packet)

		_, err = ssocket.Write([]byte("abc def"))
		if err != nil {
			log.Fatalf("Server: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Server: wrote abc def to wrapped socket")

		n, err := ssocket.Read(smallPacket[:])
		if err != nil {
			log.Fatalf("Server: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Server: the second received first part of packet is %s", smallPacket[:n])

		n, err = ssocket.Read(smallPacket[:])
		if err != nil {
			log.Fatalf("Server: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Server: the second received second part of packet is %s", smallPacket[:n])

		_, err = ssocket.Write([]byte("ABC DEF MNO PQR"))
		if err != nil {
			log.Fatalf("Server: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Server: wrote ABC DEF MNO PQR to wrapped socket")

		short, err := ssocket.ReadFrame()
		if err != nil {
			log.Fatalf("Server: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Server: the frame received is %s", short)

		_, err = ssocket.Write([]byte("SHORT"))
		if err != nil {
			log.Fatalf("Server: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Server: wrote SHORT to wrapped socket")

		err = ssocket.Close()
		if err != nil {
			log.Fatalf("Server: failed to close socket: %s", err)
		}
	}
}
