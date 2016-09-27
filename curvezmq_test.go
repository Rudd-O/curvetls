package curvetls

import (
	"golang.org/x/crypto/nacl/box"
	"testing"
)

func benchmarkMessageEncrypt(msgsize int, b *testing.B) {
	b.SetBytes(int64(msgsize))
	p, f := validParms(b), &messageCommand{}
	in := make([]byte, msgsize)
	inS := in[:]
	var err error
	for n := 0; n < b.N; n++ {
		f.build(p.sN, p.sPriv, p.cPub, inS, true)
	}
	if err != nil {
		b.Fatal(err)
	}
}

func benchmarkMessageDecrypt(msgsize int, b *testing.B) {
	b.SetBytes(int64(msgsize))
	p, f := validParms(b), &messageCommand{}
	in := make([]byte, msgsize)
	f.build(p.sN, p.sPriv, p.cPub, in[:], true)
	var err error
	for n := 0; n < b.N; n++ {
		_, err = f.validate(p.cN, p.cPriv, p.sPub, true)
		p.cN.counter -= 1
	}
	if err != nil {
		b.Fatal(err)
	}
}

func benchmarkNaclKeypairEnc(msgsize int, b *testing.B) {
	b.SetBytes(int64(msgsize))
	p, _ := validParms(b), &messageCommand{}
	in := make([]byte, msgsize)
	var nonce [24]byte
	sPriv := [32]byte(p.sPriv)
	cPub := [32]byte(p.cPub)
	for n := 0; n < b.N; n++ {
		box.Seal(nil, in, &nonce, &sPriv, &cPub)
	}
}

func benchmarkNaclKeypairDec(msgsize int, b *testing.B) {
	b.SetBytes(int64(msgsize))
	p, _ := validParms(b), &messageCommand{}
	in := make([]byte, msgsize+box.Overhead)
	var nonce [24]byte
	sPriv := [32]byte(p.sPriv)
	cPub := [32]byte(p.cPub)
	for n := 0; n < b.N; n++ {
		box.Open(nil, in, &nonce, &sPriv, &cPub)
	}
}

func BenchmarkMessageEncrypt1B(b *testing.B)   { benchmarkMessageEncrypt(1, b) }
func BenchmarkMessageEncrypt64B(b *testing.B)  { benchmarkMessageEncrypt(64, b) }
func BenchmarkMessageEncrypt1KB(b *testing.B)  { benchmarkMessageEncrypt(1024, b) }
func BenchmarkMessageEncrypt64KB(b *testing.B) { benchmarkMessageEncrypt(1024*64, b) }
func BenchmarkMessageEncrypt1MB(b *testing.B)  { benchmarkMessageEncrypt(1024*1024, b) }
func BenchmarkMessageEncrypt64MB(b *testing.B) { benchmarkMessageEncrypt(64*1024*1024, b) }

func BenchmarkMessageDecrypt1B(b *testing.B)   { benchmarkMessageDecrypt(1, b) }
func BenchmarkMessageDecrypt64B(b *testing.B)  { benchmarkMessageDecrypt(64, b) }
func BenchmarkMessageDecrypt1KB(b *testing.B)  { benchmarkMessageDecrypt(1024, b) }
func BenchmarkMessageDecrypt64KB(b *testing.B) { benchmarkMessageDecrypt(1024*64, b) }
func BenchmarkMessageDecrypt1MB(b *testing.B)  { benchmarkMessageDecrypt(1024*1024, b) }
func BenchmarkMessageDecrypt64MB(b *testing.B) { benchmarkMessageDecrypt(64*1024*1024, b) }

func BenchmarkNaclKeypairEnc1B(b *testing.B)   { benchmarkNaclKeypairEnc(1, b) }
func BenchmarkNaclKeypairEnc64KB(b *testing.B) { benchmarkNaclKeypairEnc(64*1024, b) }
func BenchmarkNaclKeypairEnc64MB(b *testing.B) { benchmarkNaclKeypairEnc(64*1024*1024, b) }

func BenchmarkNaclKeypairDec1B(b *testing.B)   { benchmarkNaclKeypairDec(1, b) }
func BenchmarkNaclKeypairDec64KB(b *testing.B) { benchmarkNaclKeypairDec(64*1024, b) }
func BenchmarkNaclKeypairDec64MB(b *testing.B) { benchmarkNaclKeypairDec(64*1024*1024, b) }
