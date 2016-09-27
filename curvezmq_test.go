package curvetls

import (
	"bytes"
	"testing"
)

var benchmarkParms = validParms(nil)

func benchmarkMessageEncryptDecrypt(msgsize int, b *testing.B) {
	b.SetBytes(int64(msgsize))
	p, f := benchmarkParms, &messageCommand{}
	in := make([]byte, msgsize)
	inS := in[:]
	var out []byte
        for n := 0; n < b.N; n++ {
		f.build(p.sN, p.sPriv, p.cPub, inS, true)
		out, _ = f.validate(p.cN, p.cPriv, p.sPub, true)
	}
	if bytes.Compare(inS, out) != 0 {
		b.Fatalf("%s != %s", inS, out)
	}
}

func BenchmarkMessageEncryptDecrypt1B(b *testing.B) { benchmarkMessageEncryptDecrypt(1, b) }
func BenchmarkMessageEncryptDecrypt64B(b *testing.B) { benchmarkMessageEncryptDecrypt(64, b) }
func BenchmarkMessageEncryptDecrypt1KB(b *testing.B) { benchmarkMessageEncryptDecrypt(1024, b) }
func BenchmarkMessageEncryptDecrypt64KB(b *testing.B) { benchmarkMessageEncryptDecrypt(1024*64, b) }
func BenchmarkMessageEncryptDecrypt1MB(b *testing.B) { benchmarkMessageEncryptDecrypt(1024*1024, b) }
func BenchmarkMessageEncryptDecrypt64MB(b *testing.B) { benchmarkMessageEncryptDecrypt(64*1024*1024, b) }

