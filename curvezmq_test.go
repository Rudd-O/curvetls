package curvetls

import (
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

