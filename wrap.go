package curvetls

import (
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

// NewLongNonce generates a long nonce for use with curvetls.WrapServer
// and curvetls.WrapClient.
// A long nonce is needed and must be unique per long-term private key,
// whether the private key belongs to the server or the client.
// Long nonces must not be reused for new private keys.
func NewLongNonce() (*longNonce, error) {
	var nonce longNonce
	n, err := rand.Reader.Read(nonce[:])
	if err != nil {
		return nil, fmt.Errorf("error reading entropy while generating long nonce: %s", err)
	}
	if n != len(nonce) {
		return nil, fmt.Errorf("short entropy read while generating long nonce")
	}
	return &nonce, nil
}

type EncryptedConn struct {
	conn           net.Conn
	myNonce        *shortNonce
	theirNonce     *shortNonce
	myPrivkey      Privkey
	theirPubkey    Pubkey
	isServer       bool
	recvFrame      []byte
	recvMessageCmd *messageCommand
	sendMessageCmd *messageCommand
}

func (w *EncryptedConn) Close() error {
	return w.conn.Close()
}

func (w *EncryptedConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *EncryptedConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

// Read reads one frame from the other side, decrypts the encrypted frame,
// then copies the bytes read to the passed slice.  If the destination buffer
// is not large enough to contain the whole received frame, then a partial
// read is made and written to the buffer, and subsequent reads will continue
// reading the remainder of the frame.
// If this function returns an error, the socket remains open, but
// (much like TLS) it is highly unlikely that, after returning an error,
// the connection will continue working.
func (w *EncryptedConn) Read(b []byte) (int, error) {
	if w.recvFrame == nil {
		frame, err := w.ReadFrame()
		if err != nil {
			return 0, nil
		}
		w.recvFrame = frame
	}
	n := copy(b, w.recvFrame)
	w.recvFrame = w.recvFrame[n:]
	if len(w.recvFrame) == 0 {
		w.recvFrame = nil
	}
	return n, nil
}

// ReadFrame reads one frame from the other side, decrypts the encrypted frame,
// then returns the whole frame as a slice of bytes.
// If this function returns an error, the socket remains open, but
// (much like TLS) it is highly unlikely that, after returning an error,
// the connection will continue working.
// It is an error to call ReadFrame when a previous Read was only partially
// written to its output buffer.
func (w *EncryptedConn) ReadFrame() ([]byte, error) {
	if w.recvFrame != nil {
		return nil, newInternalError("cannot read a frame while there is a prior partial frame buffered")
	}

	/* Read and validate message. */
	if w.recvMessageCmd == nil {
		w.recvMessageCmd = &messageCommand{}
	}
	if err := readFrame(w.conn, w.recvMessageCmd); err != nil {
		return nil, err
	}

	data, err := w.recvMessageCmd.validate(w.theirNonce, w.myPrivkey, w.theirPubkey, w.isServer)
	if err != nil {
		if err == errNonceOverflow {
			return nil, newProtocolError("%s", err)
		}
		return nil, newInternalError("invalid MESSAGE: %s", err)
	}
	return data, nil
}

// Write frames, encrypts and sends to the other side the passed bytes.
// If this function returns an error, the socket remains open, but
// (much like TLS) it is highly unlikely that, after returning an error,
// the connection will continue working.
func (w *EncryptedConn) Write(b []byte) (int, error) {
	/* Build and send message. */
	if w.sendMessageCmd == nil {
		w.sendMessageCmd = &messageCommand{}
	}
	err := w.sendMessageCmd.build(w.myNonce, w.myPrivkey, w.theirPubkey, b, w.isServer)
	if err != nil {
		if err == errNonceOverflow {
			return 0, newProtocolError("%s", err)
		}
		return 0, newInternalError("cannot build MESSAGE: %s", err)
	}

	if err := writeFrame(w.conn, w.sendMessageCmd); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *EncryptedConn) SetDeadline(t time.Time) error {
	return w.conn.SetDeadline(t)
}

func (w *EncryptedConn) SetReadDeadline(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *EncryptedConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

// Returns:
// * a net.Conn compatible object that you can use to send and
//   receive data; data sent and received will be framed and
//   encrypted.
// * the public key of the client; use this key to check that the
//   client is authorized to continue the conversation, then either
//   call Allow() to signal to the client that it is authorized, or
//   call Deny() to signal to the client that it is not authorized
//   and terminate the connection.
// * an error.
//
// Lifecycle information:
////  * If WrapServer() returns an error, the passed socket will
//   have been closed by the time this function returns.
// * Upon successful return of this function, the Close() method
//   of the returned net.Conn will also Close() the passed
//   net.Conn.
// * If you read or write any data to the underlying socket rather
//   than go through the returned socket, your data will be transmitted
//   in plaintext and the endpoint will become confused and close the
//   connection.  Don't do that.
func WrapServer(conn net.Conn,
	serverprivkey Privkey,
	serverpubkey Pubkey,
	long_nonce *longNonce) (*EncryptedConn, Pubkey, error) {

	bail := func(e error) (*EncryptedConn, Pubkey, error) {
		// These are unrecoverable errors.  We close the socket.
		conn.Close()
		return nil, Pubkey{}, e
	}

	myNonce := newShortNonce()
	clientNonce := newShortNonce()

	/* Do greeting. */
	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asServer()
	expectedgreeting.asClient()

	if err := wrc(conn, mygreeting[:], theirgreeting[:]); err != nil {
		return bail(err)
	}

	if theirgreeting != expectedgreeting {
		return bail(newProtocolError("malformed greeting"))
	}

	/* Read and validate hello. */
	var helloCmd helloCommand
	if err := readFrame(conn, &helloCmd); err != nil {
		return bail(err)
	}

	ephClientPubkey, err := helloCmd.validate(clientNonce, permanentServerPrivkey(serverprivkey))
	if err != nil {
		return bail(newProtocolError("invalid HELLO: %s", err))
	}

	/* Build and send welcome. */
	var welcomeCmd welcomeCommand
	cookieKey, err := welcomeCmd.build(long_nonce, ephClientPubkey, permanentServerPrivkey(serverprivkey))
	// FIXME: wipe memory of cookiekey after 60 seconds
	// FIXME: wipe memory of cookie, and all the ephemeral server keys at this point
	if err != nil {
		if err == errNonceOverflow {
			return bail(newProtocolError("%s", err))
		}
		return bail(newInternalError("cannot build WELCOME: %s", err))
	}

	if err := writeFrame(conn, &welcomeCmd); err != nil {
		return bail(err)
	}

	/* Read and validate initiate. */
	var initiateCmd initiateCommand
	if err := readFrame(conn, &initiateCmd); err != nil {
		return bail(err)
	}

	permClientPubkey, ephClientPubkey, ephServerPrivkey, err := initiateCmd.validate(clientNonce, permanentServerPubkey(serverpubkey), cookieKey)
	if err != nil {
		return bail(newProtocolError("invalid INITIATE: %s", err))
	}

	return &EncryptedConn{
		conn:        conn,
		myNonce:     myNonce,
		theirNonce:  clientNonce,
		myPrivkey:   Privkey(ephServerPrivkey),
		theirPubkey: Pubkey(ephClientPubkey),
		isServer:    true,
	}, Pubkey(permClientPubkey), nil
}

// Allow, when called on a server socket, signals the client that
// it is authorized to continue.
// It is an error to call Allow on a client socket.
//
// Lifecycle information:
//
// * If Allow() returns an error, the passed socket will
//   have been closed by the time this function returns.
func (c *EncryptedConn) Allow() error {
	bail := func(e error) error {
		// These are unrecoverable errors.  We close the socket.
		c.conn.Close()
		return e
	}

	/* Build and send ready. */
	var readyCmd readyCommand
	if err := readyCmd.build(c.myNonce,
		ephemeralServerPrivkey(c.myPrivkey),
		ephemeralClientPubkey(c.theirPubkey)); err != nil {
		if err == errNonceOverflow {
			return bail(newProtocolError("%s", err))
		}
		return bail(newInternalError("cannot build READY: %s", err))
	}

	if err := writeFrame(c.conn, &readyCmd); err != nil {
		return bail(err)
	}

	return nil
}

// Deny, when called on a server socket, signals the client that
// it is not authorized to continue, and closes the socket.
// It is an error to call Deny on a server socket.
//
// Lifecycle information:
//
// * If Deny() returns an error, the passed socket will
//   have been closed by the time this function returns.
// * When Deny() returns normally, the underlying socket will have
//   been closed too.
func (c *EncryptedConn) Deny() error {
	bail := func(e error) error {
		// These are unrecoverable errors.  We close the socket.
		c.conn.Close()
		return e
	}

	/* Build and send error. */
	var errorCmd errorCommand
	if err := errorCmd.build("unauthorized"); err != nil {
		if err == errNonceOverflow {
			return bail(newProtocolError("%s", err))
		}
		return bail(newInternalError("cannot build ERROR: %s", err))
	}

	if err := writeFrame(c.conn, &errorCmd); err != nil {
		return bail(err)
	}

	err := c.conn.Close()
	return err
}

// IsAuthenticationError returns true when WrapClient() was rejected by
// the server's wrapping routines for authentication reasons with Deny().
func IsAuthenticationError(e error) bool {
	_, ok := e.(*authenticationError)
	return ok
}

// Returns:
// * a net.Conn compatible object that you can use to send and
//   receive data; data sent and received will be framed and
//   encrypted.
// * an error.
//
// Lifecycle information:
//
// * If WrapClient() returns an error, the passed socket will
//   have been closed by the time this function returns.
// * Upon successful return of this function, the Close() method
//   of the returned net.Conn will also Close() the passed
//   net.Conn.
// * Upon unauthorized use (the server rejects the client with Deny())
//   this function will return an error which can be checked with
//   the function IsUnauthorized().
// * If you read or write any data to the underlying socket rather
//   than go through the returned socket, your data will be transmitted
//   in plaintext and the endpoint will become confused and close the
//   connection.  Don't do that.
func WrapClient(conn net.Conn,
	clientprivkey Privkey, clientpubkey Pubkey,
	permServerPubkey Pubkey,
	long_nonce *longNonce) (*EncryptedConn, error) {

	bail := func(e error) (*EncryptedConn, error) {
		// These are unrecoverable errors.  We close the socket.
		conn.Close()
		return nil, e
	}

	myNonce := newShortNonce()
	serverNonce := newShortNonce()

	/* Generate ephemeral keypair for this connection. */
	ephClientPrivkey, ephClientPubkey, err := genEphemeralClientKeyPair()
	if err != nil {
		return bail(newInternalError("cannot generate ephemeral keypair", err))
	}

	/* Do greeting. */
	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asClient()
	expectedgreeting.asServer()

	if err := wrc(conn, mygreeting[:], theirgreeting[:]); err != nil {
		return bail(err)
	}

	if theirgreeting != expectedgreeting {
		return bail(newProtocolError("malformed greeting"))
	}

	/* Build and send hello. */
	var helloCmd helloCommand
	if err := helloCmd.build(myNonce, ephClientPrivkey, ephClientPubkey, permanentServerPubkey(permServerPubkey)); err != nil {
		if err == errNonceOverflow {
			return bail(newProtocolError("%s", err))
		}
		return bail(newInternalError("cannot build HELLO: %s", err))
	}

	if err := writeFrame(conn, &helloCmd); err != nil {
		return bail(err)
	}

	/* Receive and validate welcome. */
	var welcomeCmd welcomeCommand
	if err := readFrame(conn, &welcomeCmd); err != nil {
		return bail(err)
	}

	ephServerPubkey, sCookie, err := welcomeCmd.validate(ephClientPrivkey, permanentServerPubkey(permServerPubkey))
	if err != nil {
		return bail(newProtocolError("invalid WELCOME: %s", err))
	}

	/* Build and send initiate. */
	var initiateCmd initiateCommand
	if err := initiateCmd.build(myNonce,
		long_nonce,
		sCookie,
		permanentClientPrivkey(clientprivkey),
		permanentClientPubkey(clientpubkey),
		permanentServerPubkey(permServerPubkey),
		ephServerPubkey,
		ephClientPrivkey,
		ephClientPubkey); err != nil {
		if err == errNonceOverflow {
			return bail(newProtocolError("%s", err))
		}
		return bail(newInternalError("cannot build INITIATE: %s", err))
	}

	if err := writeFrame(conn, &initiateCmd); err != nil {
		return bail(err)
	}

	/* Receive and validate ready. */
	var genericCmd genericCommand
	if err := readFrame(conn, &genericCmd); err != nil {
		return bail(err)
	}

	specificCmd, err := genericCmd.convert()
	if err != nil {
		return bail(newProtocolError("invalid READY or ERROR: %s", err))
	}

	switch cmd := specificCmd.(type) {
	case *readyCommand:
		if err := cmd.validate(serverNonce, ephClientPrivkey, ephServerPubkey); err != nil {
			return bail(newProtocolError("invalid READY: %s", err))
		}
	case *errorCommand:
		reason, err := cmd.validate()
		if err != nil {
			return bail(newProtocolError("invalid ERROR: %s", err))
		}
		return bail(newAuthenticationError(reason))
	default:
		return bail(newProtocolError("invalid command: %s", cmd))
	}

	return &EncryptedConn{
		conn:        conn,
		myNonce:     myNonce,
		theirNonce:  serverNonce,
		myPrivkey:   Privkey(ephClientPrivkey),
		theirPubkey: Pubkey(ephServerPubkey),
		isServer:    false,
	}, nil
}
