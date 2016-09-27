package curvetls

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/nacl/box"
)

type key [32]byte

func keyFromString(s string, t string) (p [32]byte, err error) {
	if len(s) < 1 {
		return p, fmt.Errorf("%s key is too short", t)
	}
	if t == "private" {
		if s[0] != 'p' {
			if s[0] == 'P' {
				return p, fmt.Errorf("%s key %s appears to be a public key", t, s)
			}
			return p, fmt.Errorf("%s key %s is not valid", t, s)
		}
	} else if t == "public" {
		if s[0] != 'P' {
			if s[0] == 'p' {
				return p, fmt.Errorf("%s key %s appears to be a private key", t, s)
			}
			return p, fmt.Errorf("%s key %s is not valid", t, s)
		}
	}
	s = s[1:]
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return p, err
	}
	if len(data) != 32 {
		return p, fmt.Errorf("%s key %s does not decode to 32 bytes", t, s)
	}
	copy(p[:], data)
	return p, nil
}

func keyFromSlice(s []byte, t string) (p [32]byte, err error) {
	if len(s) != 32 {
		return p, fmt.Errorf("%s key %s is not 32 bytes long", t, s)
	}
	copy(p[:], s)
	return p, nil
}

// Privkey is an opaque type representing a private key as used in curvetls.
type Privkey key

func privkeyFromSlice(s []byte) (p Privkey, err error) {
	return keyFromSlice(s, "private")
}

// PubkeyFromString deserializes a Pubkey as supplied in the string.
// See Pubkey.String() for information on the string format of Pubkeys.
//
// String format of Privkey is the letter p plus a base64 rendering
// of 32 bytes.
func PubkeyFromString(s string) (p Pubkey, err error) {
	return keyFromString(s, "public")
}

// String format of Privkey is the letter "p" plus a base64 rendering
// of 32 bytes.
func (k Privkey) String() string {
	return "p" + base64.StdEncoding.EncodeToString(k[:])
}

// Pubkey is an opaque type representing a public key as used in curvetls.
type Pubkey key

func pubkeyFromSlice(s []byte) (p Pubkey, err error) {
	return keyFromSlice(s, "public")
}

// PrivkeyFromString deserializes a Privkey as supplied in the string.
// See Privkey.String() for information on the string format of Privkeys.
func PrivkeyFromString(s string) (p Privkey, err error) {
	return keyFromString(s, "private")
}

// String format of Privkey is the letter "P" plus a base64 rendering
// of 32 bytes.
func (k Pubkey) String() string {
	return "P" + base64.StdEncoding.EncodeToString(k[:])
}

// GenKeyPair generates a pair of private and public keys as
// Privkey and Pubkey structs.
//
// It is safe to invoke this function concurrently.
func GenKeyPair() (Privkey, Pubkey, error) {
	public, private, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Privkey{}, Pubkey{}, err
	}
	pu, err := pubkeyFromSlice(public[:])
	if err != nil {
		return Privkey{}, Pubkey{}, err
	}
	pr, err := privkeyFromSlice(private[:])
	if err != nil {
		return Privkey{}, Pubkey{}, err
	}
	return pr, pu, err
}

type permanentServerPrivkey Privkey

type permanentServerPubkey Pubkey

type permanentClientPrivkey Privkey

type permanentClientPubkey Pubkey

type ephemeralServerPrivkey Privkey

type ephemeralServerPubkey Pubkey

type ephemeralClientPrivkey Privkey

type ephemeralClientPubkey Pubkey

type precomputedKey key

func genEphemeralClientKeyPair() (ephemeralClientPrivkey, ephemeralClientPubkey, error) {
	privk, pubk, err := GenKeyPair()
	return ephemeralClientPrivkey(privk), ephemeralClientPubkey(pubk), err
}

func genEphemeralServerKeyPair() (ephemeralServerPrivkey, ephemeralServerPubkey, error) {
	privk, pubk, err := GenKeyPair()
	return ephemeralServerPrivkey(privk), ephemeralServerPubkey(pubk), err
}

func precomputeKey(priv Privkey, pub Pubkey) precomputedKey {
	cpriv := [32]byte(priv)
	cpub := [32]byte(pub)
	var sk precomputedKey
	csk := [32]byte(sk)
	box.Precompute(&csk, &cpub, &cpriv)
	return sk
}
