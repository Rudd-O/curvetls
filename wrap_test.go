package curvetls

import (
	"bytes"
	"encoding/binary"
	"testing"
)

type Fataler interface {
	Fatal(...interface{})
}

func keys(t Fataler) (sPriv Privkey, sPub Pubkey,
	cPriv Privkey, cPub Pubkey) {
	var err error
	sPriv, sPub, err = GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cPriv, cPub, err = GenKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return
}

func nonces() (sN, cN *shortNonce) {
	sN, cN = newShortNonce(), newShortNonce()
	return
}

type parms struct {
	sPriv Privkey
	sPub  Pubkey
	cPriv Privkey
	cPub  Pubkey
	sN    *shortNonce
	cN    *shortNonce
}

func validParms(t Fataler) *parms {
	sPriv, sPub, cPriv, cPub := keys(t)
	sN, cN := nonces()
	return &parms{sPriv, sPub, cPriv, cPub, sN, cN}
}

func validMessageFrame(t *testing.T, p *parms, payload []byte) (f *messageCommand) {
	var err error

	f = &messageCommand{}
	err = f.build(p.sN, p.sPriv, p.cPub, payload, true)
	if err != nil {
		t.Fatal(err)
	}

	out, err := f.validate(p.cN, p.cPriv, p.sPub, true)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Compare(payload, out) != 0 {
		t.Fatalf("%s != %s", payload, out)
	}
	return
}

// fixedNonce is a type of nonce that never increments.
//
// This allows me to supply it to functions that bump the nonce, but
// have it never bump.
type fixedNonce struct {
	sn         *shortNonce
	fixedValue uint64
}

func (s *fixedNonce) prefixAndBump(prefix [16]byte) ([24]byte, [8]byte, error) {
	s.sn.counter = 0
	long, prev, err := s.sn.prefixAndBump(prefix)
	if err != nil {
		return long, prev, err
	}
	s.sn.counter = s.fixedValue
	binary.BigEndian.PutUint64(long[len(prefix):], s.fixedValue)
	binary.BigEndian.PutUint64(prev[:], s.fixedValue-1)
	return long, prev, nil
}

func newFixedNonce(val uint64) *fixedNonce {
	return &fixedNonce{newShortNonce(), val}
}

func TestMessageNonceOverflow(t *testing.T) {
	p := validParms(t)
	f := validMessageFrame(t, p, []byte("sup"))

	// Testing that message build fails when nonce overflows
	// Decrement the counter, which is at 1, to make it MAXUINT64-1
	p.sN.counter -= 2
	err := f.build(p.sN, p.sPriv, p.cPub, []byte("sup"), true)
	if err != errNonceOverflow {
		t.Errorf("%s != %s", err, errNonceOverflow)
	}

	// Testing that message validate fails when nonce overflows
	// Fix the server counter so that the outgoing nonce is 0.
	sN := newFixedNonce(0)
	err = f.build(sN, p.sPriv, p.cPub, []byte("sup"), true)
	if err != nil {
		t.Errorf("err != nil: %s", err)
	}
	// Then arrange such that the receiving side has a MAXUINT64-1
	// nonce.  This should technically "overflow" to 0, but the
	// routine that does the work should detect that and raise an error.
	p.cN.counter = 0
	p.cN.counter -= 1
	_, err = f.validate(p.cN, p.cPriv, p.sPub, true)
	if err != errNonceOverflow {
		t.Errorf("%s != %s", err, errNonceOverflow)
	}
}
