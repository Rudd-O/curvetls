package curvetls

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/secretbox"
	"net"
)

var greetingTemplate = [64]byte{
	'\xFF',
	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
	'\x7F',
	'\x03', '\x01',
	'C', 'U', 'R', 'V', 'E',
	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
	'\x00', '\x00', '\x00', '\x00', '\x00', '\x00', '\x00',
	'\x00',
}

type greeting [64]byte

func (g *greeting) asServer() {
	copy(g[:], greetingTemplate[:])
	g[32] = '\x01'
}

func (g *greeting) asClient() {
	copy(g[:], greetingTemplate[:])
	g[32] = '\x00'
}

var helloNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'H', 'E', 'L', 'L', 'O', '-', '-', '-'}
var welcomeNoncePrefix = [8]byte{'W', 'E', 'L', 'C', 'O', 'M', 'E', '-'}
var cookieNoncePrefix = [8]byte{'C', 'O', 'O', 'K', 'I', 'E', '-', '-'}
var initiateNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'I', 'n', 'i', 't', 'i', 'a', 't', 'e'}
var vouchNoncePrefix = [8]byte{'V', 'O', 'U', 'C', 'H', '-', '-', '-'}
var readyNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'R', 'E', 'A', 'D', 'Y', '-', '-', '-'}
var serverMessageNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'S'}
var clientMessageNoncePrefix = [16]byte{'C', 'u', 'r', 'v', 'e', 'Z', 'M', 'Q', 'M', 'E', 'S', 'S', 'A', 'G', 'E', 'C'}

const maxUint = ^uint(0)
const maxFrameSize = int(maxUint >> 1)

func rc(conn net.Conn, buf []byte) error {
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short read")
	}
	return nil
}

func wc(conn net.Conn, data []byte) error {
	n, err := conn.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return fmt.Errorf("short write")
	}
	return nil
}

func wrc(conn net.Conn, dataToWrite []byte, bufToReadInto []byte) error {
	err := wc(conn, dataToWrite)
	if err == nil {
		err = rc(conn, bufToReadInto)
	}
	return err
}

type shortNonce struct {
	counter uint64
}

func newShortNonce() *shortNonce {
	return &shortNonce{}
}

func readShortNonce(data []byte) (*shortNonce, error) {
	if len(data) != 8 {
		return nil, fmt.Errorf("invalid nonce read")
	}
	var n shortNonce
	n.counter = binary.BigEndian.Uint64(data)
	return &n, nil
}

func (s *shortNonce) prefixAndBump(prefix [16]byte) ([24]byte, [8]byte, error) {
	var contents [24]byte
	var previousNonceContents [8]byte
	copy(contents[:], prefix[:])
	binary.BigEndian.PutUint64(contents[len(prefix):], s.counter)
	binary.BigEndian.PutUint64(previousNonceContents[:], s.counter)
	s.counter += 1
	if s.counter == 0 {
		return contents, previousNonceContents, errNonceOverflow
	}
	return contents, previousNonceContents, nil
}

type longNonce [16]byte

func (s *longNonce) prefix(prefix [8]byte) [24]byte {
	/* Return a 24-byte combined prefix and long nonce. */
	var fullNonce [24]byte
	copy(fullNonce[:8], prefix[:])
	copy(fullNonce[8:], s[:])
	return fullNonce
}

func (s *longNonce) writeUnprefixed(dest []byte) error {
	/* Write the 16-byte long nonce write to dest. */
	if len(dest) != 16 {
		return fmt.Errorf("incorrect nonce destination length")
	}
	if copy(dest, s[:]) != len(s) {
		return fmt.Errorf("short nonce generation")
	}
	return nil
}

func readLongNonce(src []byte) (*longNonce, error) {
	if len(src) != 16 {
		return nil, fmt.Errorf("invalid nonce read")
	}
	var n longNonce
	copy(n[:], src)
	return &n, nil
}

func (s *shortNonce) uint64() uint64 {
	return s.counter
}

func (s *shortNonce) same(s2 *shortNonce) bool {
	return s.counter == s2.counter
}

type serverCookie [96]byte
type serverCookieKey [32]byte

func getCookieKey() (k serverCookieKey, err error) {
	// FIXME move everything to pointers and clear cookie key, ephemeral server keys.
	n, err := rand.Reader.Read(k[:])
	if err != nil {
		return k, fmt.Errorf("error reading entropy while generating cookie key: %s", err)
	}
	if n != len(k) {
		return k, fmt.Errorf("short entropy read while generating cookie key")
	}
	return k, nil
}

func newServerCookie(ln *longNonce, cpub ephemeralClientPubkey, spriv ephemeralServerPrivkey) (serverCookie, serverCookieKey, error) {
	var s serverCookie
	var unenccookiebox [64]byte
	copy(unenccookiebox[:32], cpub[:])
	copy(unenccookiebox[32:], spriv[:])
	cookieKey, err := getCookieKey()
	if err != nil {
		return s, [32]byte{}, err
	}
	prefixedNonce := ln.prefix(cookieNoncePrefix)
	ck := [32]byte(cookieKey)
	enccookiebox := secretbox.Seal(nil, unenccookiebox[:], &prefixedNonce, &ck)
	if err := ln.writeUnprefixed(s[:16]); err != nil {
		return s, [32]byte{}, err
	}
	copy(s[16:], enccookiebox)
	return s, cookieKey, nil
}

func (s *serverCookie) decrypt(cookieKey [32]byte) (ephemeralClientPubkey, ephemeralServerPrivkey, bool, error) {
	ln, err := readLongNonce(s[:16])
	if err != nil {
		return ephemeralClientPubkey{}, ephemeralServerPrivkey{}, false, err
	}
	prefixedNonce := ln.prefix(cookieNoncePrefix)
	unenccookiebox, ok := secretbox.Open(nil, s[16:], &prefixedNonce, &cookieKey)
	if !ok {
		return ephemeralClientPubkey{}, ephemeralServerPrivkey{}, false, nil
	}
	var cpub ephemeralClientPubkey
	var spriv ephemeralServerPrivkey
	copy(cpub[:], unenccookiebox[:32])
	copy(spriv[:], unenccookiebox[32:])
	return cpub, spriv, true, nil
}

type clientVouch [96]byte

func newClientVouch(ln *longNonce,
	ecp ephemeralClientPubkey,
	psp permanentServerPubkey,
	esp ephemeralServerPubkey,
	pcp permanentClientPrivkey) (clientVouch, error) {
	var s clientVouch
	var unenckeybox [64]byte
	copy(unenckeybox[:32], ecp[:])
	copy(unenckeybox[32:], psp[:])
	prefixedNonce := ln.prefix(vouchNoncePrefix)
	Sprime := [32]byte(esp)
	C := [32]byte(pcp)
	enckeybox := box.Seal(nil, unenckeybox[:], &prefixedNonce, &Sprime, &C)
	if err := ln.writeUnprefixed(s[:16]); err != nil {
		return s, err
	}
	copy(s[16:], enckeybox)
	return s, nil
}

func (c *clientVouch) decrypt(pc permanentClientPubkey,
	es ephemeralServerPrivkey) (ephemeralClientPubkey, permanentServerPubkey, bool, error) {
	ln, err := readLongNonce(c[:16])
	if err != nil {
		return ephemeralClientPubkey{}, permanentServerPubkey{}, false, err
	}
	prefixedNonce := ln.prefix(vouchNoncePrefix)
	C := [32]byte(pc)
	Sprime := [32]byte(es)
	unencvouchbox, ok := box.Open(nil, c[16:], &prefixedNonce, &C, &Sprime)
	if !ok {
		return ephemeralClientPubkey{}, permanentServerPubkey{}, false, nil
	}
	var ecp ephemeralClientPubkey
	var spub permanentServerPubkey
	copy(ecp[:], unencvouchbox[:32])
	copy(spub[:], unencvouchbox[32:])
	return ecp, spub, true, nil
}

type protocolError struct {
	reason string
}

func newProtocolError(reason string, additional ...interface{}) error {
	return &protocolError{fmt.Sprintf(reason, additional...)}
}

func (p *protocolError) Error() string {
	return p.reason
}

type internalError struct {
	reason string
}

func newInternalError(reason string, additional ...interface{}) error {
	return &internalError{fmt.Sprintf(reason, additional...)}
}

func (p *internalError) Error() string {
	return p.reason
}

type authenticationError struct {
	reason string
}

func newAuthenticationError(reason string) error {
	return &authenticationError{reason}
}

func (p *authenticationError) Error() string {
	return p.reason
}

// errTooBig is returned when realloc cannot grow the buffer to the
// requested value.
var errTooBig = errors.New("requested buffer cannot be that big")

// errNonceOverflow is returned when the nonce for this side of the connection
// has overflown (gone back to zero).
var errNonceOverflow = errors.New("nonce overflow")

type frame interface {
	getBuffer() []byte
	// realloc attempts to reallocate the buffer associated with getBuffer
	// and returns one of three tuples:
	//
	// * false, nil when the buffer is fixed and may not be reallocated
	// * true, non-nil when the buffer cannot attain the requested size
	// * true, nil when the buffer was successfully reallocated
	//
	// After reallocation, any previous references taken to the result of
	// previous getBuffer() calls are invalid and will be unsafe to use.
	realloc(uint64) (bool, error)
}

func readFrame(conn net.Conn, dest frame) error {
	var ftype [1]byte
	if err := rc(conn, ftype[:]); err != nil {
		return err
	}
	var uint64len uint64
	if ftype[0] == '\004' {
		var length [1]uint8
		if err := rc(conn, length[:]); err != nil {
			return err
		}
		uint64len = uint64(length[0])
	} else if ftype[0] == '\006' {
		var length [8]byte
		if err := rc(conn, length[:]); err != nil {
			return err
		}
		uint64len = binary.BigEndian.Uint64(length[:])
	} else {
		return newProtocolError("unsupported frame type %d", uint8(ftype[0]))
	}
	buf := dest.getBuffer()
	if uint64(len(buf)) != uint64len {
		canRealloc, err := dest.realloc(uint64len)
		// Replicated in genericFrame.convert().  FIXME dedup.
		if !canRealloc {
			return newProtocolError("sender says frame is %d bytes, buffer is %d bytes", uint64len, len(buf))
		}
		if err != nil {
			return newProtocolError("realloc for destination buffer from %d to %d failed: %s", len(buf), uint64len, err)
		}
		/* At this point, the buffer has been reallocated */
		buf = dest.getBuffer()
	}
	if err := rc(conn, buf); err != nil {
		return err
	}
	return nil
}

func writeFrame(conn net.Conn, src frame) error {
	buf := src.getBuffer()
	length := len(buf)
	if length < 256 {
		/* Short frame send routine */
		if err := wc(conn, []byte{'\004'}); err != nil {
			return err
		}
		var uintlength uint8
		uintlength = uint8(length)
		if err := wc(conn, []byte{uintlength}); err != nil {
			return err
		}
		if err := wc(conn, buf); err != nil {
			return err
		}
		return nil
	}
	if err := wc(conn, []byte{'\006'}); err != nil {
		return err
	}
	var uintlength [8]byte
	binary.BigEndian.PutUint64(uintlength[:], uint64(length))
	if err := wc(conn, uintlength[:]); err != nil {
		return err
	}
	if err := wc(conn, buf); err != nil {
		return err
	}
	return nil
}

type helloCommand struct {
	buf [200]byte
}

func (h *helloCommand) getBuffer() []byte {
	return h.buf[:]
}

func (h *helloCommand) realloc(uint64) (bool, error) {
	return false, nil
}

// build Builds a HELLO command, incrementing the passed nonce.
// This executes on the client and its result is sent to the server.
// Arguments:
//     clientShortNonce: the short nonce associated with the client,
//                       which gets incremented as this function executes.
//     ephClientPrivkey: the ephemeral client private key
//     ephClientPubkey: the ephemeral client public key
//     permServerPubkey: the permanent server public key
// Returns:
//     error: an error
func (h *helloCommand) build(
	clientShortNonce *shortNonce,
	ephClientPrivkey ephemeralClientPrivkey,
	ephClientPubkey ephemeralClientPubkey,
	permServerPubkey permanentServerPubkey) error {

	destHeader := h.buf[:8]
	destEphClientPubkey := h.buf[80 : 80+32]
	destUnprefixedNonce := h.buf[80+32 : 80+32+8]
	destEncHelloBox := h.buf[80+32+8 : 80+32+8+80]

	prefixedNonce, unprefixedNonce, err := clientShortNonce.prefixAndBump(helloNoncePrefix)
	if err != nil {
		return err
	}

	Cprime := [32]byte(ephClientPrivkey)
	S := [32]byte(permServerPubkey)
	var helloBox [64]byte
	encHelloBox := box.Seal(nil, helloBox[:], &prefixedNonce, &S, &Cprime)

	copy(destHeader, []byte{5, 'H', 'E', 'L', 'L', 'O', 1, 0})
	copy(destEphClientPubkey, ephClientPubkey[:])
	copy(destUnprefixedNonce, unprefixedNonce[:])
	copy(destEncHelloBox, encHelloBox)

	return nil
}

func (h *helloCommand) validate(expectedClientShortNonce *shortNonce,
	permServerPrivkey permanentServerPrivkey) (ephemeralClientPubkey, error) {
	/*
	 Validates a read HELLO command, incrementing the passed nonce.
	 This executes on the server
	*/

	srcHeader := h.buf[:8]
	srcPadding := h.buf[8:80]
	srcEphClientPubkey := h.buf[80 : 80+32]
	srcUnprefixedNonce := h.buf[80+32 : 80+32+8]
	srcEncHelloBox := h.buf[80+32+8 : 80+32+8+80]

	if bytes.Compare(srcHeader, []byte{5, 'H', 'E', 'L', 'L', 'O', 1, 0}) != 0 {
		return ephemeralClientPubkey{}, fmt.Errorf("malformed HELLO header")
	}
	var pa [72]byte
	if bytes.Compare(srcPadding, pa[:]) != 0 {
		return ephemeralClientPubkey{}, fmt.Errorf("malformed HELLO padding")
	}
	pk, err := pubkeyFromSlice(srcEphClientPubkey)
	if err != nil {
		return ephemeralClientPubkey{}, fmt.Errorf("invalid ephemeral client public key")
	}
	ephClientPubkey := ephemeralClientPubkey(pk)

	cn, err := readShortNonce(srcUnprefixedNonce)
	if err != nil {
		return ephemeralClientPubkey{}, err
	}
	if !expectedClientShortNonce.same(cn) {
		return ephemeralClientPubkey{}, fmt.Errorf("client nonce not in sequence: %d != %d", expectedClientShortNonce.uint64(), cn)
	}
	prefixedNonce, _, err := expectedClientShortNonce.prefixAndBump(helloNoncePrefix)
	if err != nil {
		return ephemeralClientPubkey{}, err
	}

	Cprime := [32]byte(ephClientPubkey)
	S := [32]byte(permServerPrivkey)
	helloBox, ok := box.Open(nil, srcEncHelloBox, &prefixedNonce, &Cprime, &S)
	if !ok {
		return ephemeralClientPubkey{}, fmt.Errorf("cannot validate client hello box")
	}
	var expectedHelloBox [64]byte
	if bytes.Compare(helloBox, expectedHelloBox[:]) != 0 {
		return ephemeralClientPubkey{}, fmt.Errorf("client box contains unexpected contents")
	}

	return ephClientPubkey, nil
}

type welcomeCommand struct {
	buf [168]byte
}

func (c *welcomeCommand) getBuffer() []byte {
	return c.buf[:]
}

func (h *welcomeCommand) realloc(uint64) (bool, error) {
	return false, nil
}

// Builds a WELCOME command.
// This executes in the server.
func (c *welcomeCommand) build(
	serverLongNonce *longNonce,
	ephClientPubkey ephemeralClientPubkey,
	permServerPrivkey permanentServerPrivkey) (serverCookieKey, error) {

	destHeader := c.buf[:8]
	destUnprefixedLongNonce := c.buf[8 : 8+16]
	destEncWelcomeBox := c.buf[8+16 : 168]

	ephServerPrivkey, p, err := genEphemeralServerKeyPair()
	if err != nil {
		return serverCookieKey{}, fmt.Errorf("cannot generate ephemeral keypair", err)
	}
	ephServerPubkey := ephemeralServerPubkey(p)

	cookie, cookieKey, err := newServerCookie(serverLongNonce, ephClientPubkey, ephServerPrivkey)
	if err != nil {
		return serverCookieKey{}, err
	}

	var unencwelcomebox [32 + 96]byte
	copy(unencwelcomebox[:32], ephServerPubkey[:])
	copy(unencwelcomebox[32:], cookie[:])

	Cprime := [32]byte(ephClientPubkey)
	S := [32]byte(permServerPrivkey)
	prefixedNonce := serverLongNonce.prefix(welcomeNoncePrefix)
	encWelcomeBox := box.Seal(nil, unencwelcomebox[:], &prefixedNonce, &Cprime, &S)

	copy(destHeader, []byte{7, 'W', 'E', 'L', 'C', 'O', 'M', 'E'})
	if err := serverLongNonce.writeUnprefixed(destUnprefixedLongNonce); err != nil {
		return serverCookieKey{}, err
	}
	copy(destEncWelcomeBox, encWelcomeBox)

	return cookieKey, nil
}

// Validates a read WELCOME command, incrementing the passed nonce.
// This is executed in the client.
// Returns:
//     the ephemeral server public key
//     the server cookie
//     any error that may have happened
func (c *welcomeCommand) validate(ephclientprivkey ephemeralClientPrivkey,
	permServerPubkey permanentServerPubkey) (ephemeralServerPubkey, serverCookie, error) {
	srcHeader := c.buf[:8]
	srcUnprefixedLongNonce := c.buf[8 : 8+16]
	srcEncWelcomeBox := c.buf[8+16 : 168]

	if bytes.Compare(srcHeader, []byte{7, 'W', 'E', 'L', 'C', 'O', 'M', 'E'}) != 0 {
		return ephemeralServerPubkey{}, serverCookie{}, fmt.Errorf("malformed HELLO header")
	}

	serverLongNonce, err := readLongNonce(srcUnprefixedLongNonce)
	if err != nil {
		return ephemeralServerPubkey{}, serverCookie{}, err
	}
	Cprime := [32]byte(permServerPubkey)
	S := [32]byte(ephclientprivkey)
	prefixedNonce := serverLongNonce.prefix(welcomeNoncePrefix)
	welcomeBox, ok := box.Open(nil, srcEncWelcomeBox, &prefixedNonce, &Cprime, &S)
	if !ok {
		return ephemeralServerPubkey{}, serverCookie{}, nil
	}
	srcEphServerPubkey := welcomeBox[:32]
	srcCookie := welcomeBox[32:]
	var ephServerPubkey ephemeralServerPubkey
	var sCookie serverCookie
	copy(ephServerPubkey[:], srcEphServerPubkey)
	copy(sCookie[:], srcCookie)

	return ephServerPubkey, sCookie, nil
}

type initiateCommand struct {
	// FIXME: to support metadata, bump the size of this buffer.
	buf    [257]byte
	curlen uint64
}

func (c *initiateCommand) getBuffer() []byte {
	return c.buf[:c.curlen]
}

func (c *initiateCommand) realloc(l uint64) (bool, error) {
	if l > uint64(len(c.buf)) {
		return true, errTooBig
	}
	c.curlen = l
	return true, nil
}

// Builds an INITIATE command, incrementing the passed nonce.
// This executes on the client.
func (c *initiateCommand) build(clientShortNonce *shortNonce,
	clientLongNonce *longNonce,
	cookie serverCookie,
	permClientPrivkey permanentClientPrivkey,
	permClientPubkey permanentClientPubkey,
	permServerPubkey permanentServerPubkey,
	ephServerPubkey ephemeralServerPubkey,
	ephClientPrivkey ephemeralClientPrivkey,
	ephClientPubkey ephemeralClientPubkey) error {

	// FIXME: to support metadata, bump the size of this buffer.
	_, err := c.realloc(257)
	if err != nil {
		return err
	}

	destHeader := c.buf[:9]
	destCookie := c.buf[9 : 9+96]
	destUnprefixedNonce := c.buf[9+96 : 9+96+8]
	destEncInitiateBox := c.buf[9+96+8 : 9+96+8+144]

	prefixedNonce, unprefixedNonce, err := clientShortNonce.prefixAndBump(initiateNoncePrefix)
	if err != nil {
		return err
	}

	vouch, err := newClientVouch(clientLongNonce, ephClientPubkey, permServerPubkey, ephServerPubkey, permClientPrivkey)
	if err != nil {
		return err
	}

	var initiateBox [32 + 96]byte
	copy(initiateBox[:32], permClientPubkey[:])
	copy(initiateBox[32:], vouch[:])

	Cprime := [32]byte(ephClientPrivkey)
	Sprime := [32]byte(ephServerPubkey)

	encInitiateBox := box.Seal(nil, initiateBox[:], &prefixedNonce, &Sprime, &Cprime)

	copy(destHeader, []byte{8, 'I', 'N', 'I', 'T', 'I', 'A', 'T', 'E'})
	copy(destCookie, cookie[:])
	copy(destUnprefixedNonce, unprefixedNonce[:])
	copy(destEncInitiateBox, encInitiateBox)

	return nil
}

// Validates a read WELCOME command, incrementing the passed nonce.
// This is executed in the server.
func (c *initiateCommand) validate(expectedClientShortNonce *shortNonce, expectedPermServerPubkey permanentServerPubkey,
	cookieKey [32]byte) (permanentClientPubkey, ephemeralClientPubkey, ephemeralServerPrivkey, error) {

	// FIXME: to support metadata, bump the size of this buffer.
	if c.curlen != 257 {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("wrong INITIATE length %d", c.curlen)
	}

	srcHeader := c.buf[:9]
	srcReceivedCookie := c.buf[9 : 9+96]
	srcUnprefixedNonce := c.buf[9+96 : 9+96+8]
	srcEncInitiateBox := c.buf[9+96+8 : 9+96+8+144]

	/* Validate the header. */
	if bytes.Compare(srcHeader, []byte{8, 'I', 'N', 'I', 'T', 'I', 'A', 'T', 'E'}) != 0 {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("malformed INITIATE header")
	}

	/* Check the nonce. */
	cn, err := readShortNonce(srcUnprefixedNonce)
	if err != nil {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, err
	}
	if !expectedClientShortNonce.same(cn) {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("client nonce not in sequence: %d != %d", expectedClientShortNonce.uint64(), cn)
	}
	prefixedNonce, _, err := expectedClientShortNonce.prefixAndBump(initiateNoncePrefix)
	if err != nil {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, err
	}

	/* Decrypt the cookie, get client's ephemeral pubkey and my own ephemeral privkey . */
	var cookie serverCookie
	copy(cookie[:], srcReceivedCookie)
	ephClientPubkeyFromCookie, ephServerPrivkeyFromCookie, ok, err := cookie.decrypt(cookieKey)
	if err != nil {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, err
	}
	if !ok {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("cannot validate cookie")
	}

	/* Decrypt the initiate box. */
	Cprime := [32]byte(ephClientPubkeyFromCookie)
	Sprime := [32]byte(ephServerPrivkeyFromCookie)
	initiateBox, ok := box.Open(nil, srcEncInitiateBox, &prefixedNonce, &Cprime, &Sprime)
	if !ok {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("cannot validate client initiate box")
	}

	/* Get permanent client pubkey aend encrypted vouch from initiate box */
	var permClientPubkey permanentClientPubkey
	var vouch clientVouch
	copy(permClientPubkey[:], initiateBox[:32])
	copy(vouch[:], initiateBox[32:])

	/* Decrypt the vouch, get client's ephemeral pubkey and server's permanent pubkey. */
	ephClientPubkeyFromVouch, permServerPubkeyFromVouch, ok, err := vouch.decrypt(permClientPubkey, ephServerPrivkeyFromCookie)
	if err != nil {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, err
	}
	if !ok {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("cannot validate client vouch")
	}

	/* Validate keys. */
	if ephClientPubkeyFromCookie != ephClientPubkeyFromVouch {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("ephemeral client public keys differ between cookie and vouch")
	}
	if permServerPubkeyFromVouch != expectedPermServerPubkey {
		return permanentClientPubkey{}, ephemeralClientPubkey{}, ephemeralServerPrivkey{}, fmt.Errorf("permanent server public keys differ between cookie and vouch")
	}

	return permClientPubkey, ephClientPubkeyFromVouch, ephServerPrivkeyFromCookie, nil
}

type readyCommand struct {
	// FIXME: to support metadata, bump the size of this buffer.
	buf    [30]byte
	curlen uint64
}

func (c *readyCommand) getBuffer() []byte {
	return c.buf[:c.curlen]
}

func (c *readyCommand) realloc(l uint64) (bool, error) {
	if l > uint64(len(c.buf)) {
		return true, errTooBig
	}
	c.curlen = l
	return true, nil
}

// Builds a READY command, incrementing the passed nonce.
// This executes on the client.
func (c *readyCommand) build(serverShortNonce *shortNonce,
	ephServerPrivkey ephemeralServerPrivkey,
	ephClientPubkey ephemeralClientPubkey) error {

	// FIXME: to support metadata, bump the size of this buffer.
	_, err := c.realloc(30)
	if err != nil {
		return err
	}

	destHeader := c.buf[:6]
	destUnprefixedNonce := c.buf[6 : 6+8]
	destEncReadyBox := c.buf[6+8 : 6+8+16]

	prefixedNonce, unprefixedNonce, err := serverShortNonce.prefixAndBump(readyNoncePrefix)
	if err != nil {
		return err
	}

	Cprime := [32]byte(ephClientPubkey)
	Sprime := [32]byte(ephServerPrivkey)
	encReadyBox := box.Seal(nil, []byte{}, &prefixedNonce, &Cprime, &Sprime)

	copy(destHeader, []byte{5, 'R', 'E', 'A', 'D', 'Y'})
	copy(destUnprefixedNonce, unprefixedNonce[:])
	copy(destEncReadyBox, encReadyBox)

	return nil
}

// Validates a read READY command, incrementing the passed nonce.
// This executes in the client.
func (c *readyCommand) validate(expectedServerShortNonce *shortNonce,
	ephClientPrivkey ephemeralClientPrivkey,
	ephServerPubkey ephemeralServerPubkey) error {

	// FIXME: to support metadata, bump the size of this buffer.
	if c.curlen != 30 {
		return fmt.Errorf("wrong READY length %d", c.curlen)
	}

	srcHeader := c.buf[:6]
	srcUnprefixedNonce := c.buf[6 : 6+8]
	srcEncReadyBox := c.buf[6+8 : 6+8+16]

	/* Validate the header. */
	if bytes.Compare(srcHeader, []byte{5, 'R', 'E', 'A', 'D', 'Y'}) != 0 {
		return fmt.Errorf("malformed READY header")
	}

	/* Check the nonce. */
	cn, err := readShortNonce(srcUnprefixedNonce)
	if err != nil {
		return err
	}
	if !expectedServerShortNonce.same(cn) {
		return fmt.Errorf("server nonce not in sequence: %d != %d", expectedServerShortNonce.uint64(), cn)
	}
	prefixedNonce, _, err := expectedServerShortNonce.prefixAndBump(readyNoncePrefix)
	if err != nil {
		return err
	}

	/* Decrypt the ready box. */
	Sprime := [32]byte(ephServerPubkey)
	Cprime := [32]byte(ephClientPrivkey)
	_, ok := box.Open(nil, srcEncReadyBox, &prefixedNonce, &Sprime, &Cprime)
	if !ok {
		return fmt.Errorf("cannot validate server ready box")
	}

	return nil
}

type errorCommand struct {
	buf    [256 + 6]byte
	curlen uint64
}

func (c *errorCommand) getBuffer() []byte {
	return c.buf[:c.curlen]
}

func (c *errorCommand) realloc(l uint64) (bool, error) {
	if l > uint64(len(c.buf)) {
		return true, errTooBig
	}
	c.curlen = l
	return true, nil
}

// Builds an ERROR command.
// This executes on the server.
func (c *errorCommand) build(reason string) error {

	if len(reason) > 255 {
		return fmt.Errorf("error message too long")
	}

	size := 6 + 1 + len(reason)
	_, err := c.realloc(uint64(size))
	if err != nil {
		return err
	}
	copy(c.buf[:6], []byte{5, 'E', 'R', 'R', 'O', 'R'})
	c.buf[6] = uint8(len(reason))
	copy(c.buf[7:size], []byte(reason))

	return nil
}

// Validates a read ERROR command, incrementing the passed nonce.
// This executes on the client.
func (c *errorCommand) validate() (string, error) {

	if c.curlen > 256+6 {
		return "", fmt.Errorf("invalid ERROR length %d", c.curlen)
	}
	if c.curlen < 7 {
		return "", fmt.Errorf("invalid ERROR length %d", c.curlen)
	}

	srcHeader := c.buf[:6]
	srcReasonSize := c.buf[6:7]
	srcReason := c.buf[7:c.curlen]

	/* Validate the header. */
	if bytes.Compare(srcHeader, []byte{5, 'E', 'R', 'R', 'O', 'R'}) != 0 {
		return "", fmt.Errorf("malformed ERROR header")
	}

	reasonSize := uint8(srcReasonSize[0])
	if int(reasonSize) != len(srcReason) {
		return "", fmt.Errorf("unexpected length for the reason: %d != %d", reasonSize, len(srcReason))
	}

	reason := string(srcReason)

	return reason, nil
}

type messageCommand struct {
	buf []byte
}

func (c *messageCommand) getBuffer() []byte {
	return c.buf
}

func (c *messageCommand) realloc(sz uint64) (bool, error) {
	if sz > uint64(maxFrameSize) {
		return true, errTooBig
	}

	if c.buf == nil {
		c.buf = make([]byte, sz)
		return true, nil
	}
	if uint64(cap(c.buf)) < sz {
		c.buf = make([]byte, sz)
		return true, nil
	}
	if uint64(len(c.buf)) != sz {
		c.buf = c.buf[:sz]
	}
	return true, nil
}

// Builds a MESSAGE command.
// This executes on both the server and the client.
func (c *messageCommand) build(sn *shortNonce, priv Privkey, pub Pubkey, data []byte, serverSending bool) error {

	total := uint64(8 + 8 + 16 + 1)
	total += uint64(len(data))

	_, err := c.realloc(total)
	if err != nil {
		return err
	}

	destHeader := c.buf[:8]
	destUnprefixedNonce := c.buf[8:16]
	destEncMessageBox := c.buf[16:total]

	var prefix [16]byte
	if serverSending {
		prefix = serverMessageNoncePrefix
	} else {
		prefix = clientMessageNoncePrefix
	}
	prefixedNonce, unprefixedNonce, err := sn.prefixAndBump(prefix)
	if err != nil {
		return err
	}

	Cprime := [32]byte(pub)
	Sprime := [32]byte(priv)

	data = append([]byte{0}, data...)
	encMessageBox := box.Seal(nil, data, &prefixedNonce, &Cprime, &Sprime)

	copy(destHeader, []byte{7, 'M', 'E', 'S', 'S', 'A', 'G', 'E'})
	copy(destUnprefixedNonce, unprefixedNonce[:])
	copy(destEncMessageBox, encMessageBox)

	return nil
}

// Validates a read MESSAGE command, incrementing the passed nonce.
// This executes on both the server and the client.
func (c *messageCommand) validate(expectedNonce *shortNonce, priv Privkey, pub Pubkey, serverSending bool) ([]byte, error) {

	if len(c.buf) < 33 {
		return nil, fmt.Errorf("short or malformed MESSAGE")
	}

	srcHeader := c.buf[:8]
	srcUnprefixedNonce := c.buf[8:16]
	srcEncMessageBox := c.buf[16:]

	/* Validate the header. */
	if bytes.Compare(srcHeader, []byte{7, 'M', 'E', 'S', 'S', 'A', 'G', 'E'}) != 0 {
		return nil, fmt.Errorf("malformed MESSAGE header")
	}

	/* Check the nonce. */
	cn, err := readShortNonce(srcUnprefixedNonce)
	if err != nil {
		return nil, err
	}
	if !expectedNonce.same(cn) {
		return nil, fmt.Errorf("nonce not in sequence: %d != %d", expectedNonce.uint64(), cn)
	}

	var prefix [16]byte
	if !serverSending {
		prefix = serverMessageNoncePrefix
	} else {
		prefix = clientMessageNoncePrefix
	}
	prefixedNonce, _, err := expectedNonce.prefixAndBump(prefix)
	if err != nil {
		return nil, err
	}

	/* Decrypt the ready box. */
	Sprime := [32]byte(pub)
	Cprime := [32]byte(priv)
	data, ok := box.Open(nil, srcEncMessageBox, &prefixedNonce, &Sprime, &Cprime)
	if !ok {
		return nil, fmt.Errorf("malformed MESSAGE payload")
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("malformed MESSAGE payload")
	}
	if data[0] != 0 {
		return nil, fmt.Errorf("unsupported payload flags %d", data[0])
	}

	return data[1:], nil
}

type genericCommand struct {
	buf    [4088]byte
	curlen uint64
}

func (c *genericCommand) getBuffer() []byte {
	return c.buf[:c.curlen]
}

func (c *genericCommand) realloc(l uint64) (bool, error) {
	if l > uint64(len(c.buf)) {
		return true, errTooBig
	}
	c.curlen = l
	return true, nil
}

func (c *genericCommand) convert() (frame, error) {
	var realCmd frame
	if c.curlen >= 30 && bytes.Compare(c.buf[:6], []byte{5, 'R', 'E', 'A', 'D', 'Y'}) == 0 {
		realCmd = &readyCommand{}
	} else if c.curlen >= 7 && bytes.Compare(c.buf[:6], []byte{5, 'E', 'R', 'R', 'O', 'R'}) == 0 {
		realCmd = &errorCommand{}
	} else {
		return nil, fmt.Errorf("unknown command")
	}

	buf := realCmd.getBuffer()
	if uint64(len(buf)) != c.curlen {
		// Replicated in readFrame().  FIXME dedup.
		canRealloc, err := realCmd.realloc(c.curlen)
		if !canRealloc {
			return nil, fmt.Errorf("sender says frame is %d bytes, buffer is %d bytes", c.curlen, len(buf))
		}
		if err != nil {
			return nil, fmt.Errorf("realloc for destination buffer from %d to %d failed: %s", len(buf), c.curlen, err)
		}
	}
	buf = realCmd.getBuffer()
	copy(realCmd.getBuffer(), c.getBuffer())
	return realCmd, nil
}
