package main

import (
	"github.com/Rudd-O/curvetls"
	"log"
	"net"
	"os"
)

func main() {
	if len(os.Args) < 5 {
		log.Fatalf("usage: curvetls-client <IP:port> <client privkey> <client pubkey> <server pubkey>")
	}

	connect := os.Args[1]
	clientPrivkey, err := curvetls.PrivkeyFromString(os.Args[2])
	if err != nil {
		log.Fatalf("Client: failed to parse client private key: %s", err)
	}
	clientPubkey, err := curvetls.PubkeyFromString(os.Args[3])
	if err != nil {
		log.Fatalf("Client: failed to parse client public key: %s", err)
	}
	serverPubkey, err := curvetls.PubkeyFromString(os.Args[4])
	if err != nil {
		log.Fatalf("Client: failed to parse server public key: %s", err)
	}

	socket, err := net.Dial("tcp4", connect)
	if err != nil {
		log.Fatalf("Client: failed to connect to socket: %s", err)
	}

	long_nonce, err := curvetls.NewLongNonce()
	if err != nil {
		log.Fatalf("Failed to generate nonce: %s", err)
	}
	ssocket, err := curvetls.WrapClient(socket, clientPrivkey, clientPubkey, serverPubkey, long_nonce)
	if err != nil {
		if curvetls.IsAuthenticationError(err) {
			log.Fatalf("Client: server says unauthorized: %s", err)
		} else {
			log.Fatalf("Client: failed to wrap socket: %s", err)
		}
	}

	if err == nil {
		_, err = ssocket.Write([]byte("ghi jkl"))
		if err != nil {
			log.Fatalf("Client: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Client: wrote ghi jkl to wrapped socket")

		var packet [8]byte
		var smallPacket [8]byte

		_, err = ssocket.Read(packet[:])
		if err != nil {
			log.Fatalf("Client: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Client: the first received packet is %s", packet)

		_, err = ssocket.Write([]byte("GHI JKL STU VWX "))
		if err != nil {
			log.Fatalf("Client: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Client: wrote GHI JKL STU VWX to wrapped socket")

		n, err := ssocket.Read(smallPacket[:])
		if err != nil {
			log.Fatalf("Client: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Client: the second received first part of packet is %s", smallPacket[:n])

		n, err = ssocket.Read(smallPacket[:])
		if err != nil {
			log.Fatalf("Server: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Client: the second received second part of packet is %s", smallPacket[:n])

		_, err = ssocket.Write([]byte("SHORT"))
		if err != nil {
			log.Fatalf("Client: failed to write to wrapped socket: %s", err)
		}

		log.Printf("Client: wrote SHORT to wrapped socket")

		short, err := ssocket.ReadFrame()
		if err != nil {
			log.Fatalf("Client: failed to read from wrapped socket: %s", err)
		}

		log.Printf("Client: the frame received is %s", short)

		err = ssocket.Close()
		if err != nil {
			log.Fatalf("Client: failed to close socket: %s", err)
		}
	}
}
