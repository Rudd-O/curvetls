package curvetls

import (
	"context"
	"errors"
	"net"

	"google.golang.org/grpc/credentials"
)

// KeyStore can be implemented to pass an object to validate client public keys.
type KeyStore interface {
	Allowed(Pubkey) bool
}

// NewGRPCServerCredentials constructs our GRPCCredentials type. Passing a nil
// KeyStore is valid, but in that case the server will not validate the client.
func NewGRPCServerCredentials(pubKey Pubkey, privKey Privkey, keyStore KeyStore) GRPCCredentials {
	return GRPCCredentials{
		Pub:      pubKey,
		Priv:     privKey,
		KeyStore: keyStore,
	}
}

// NewGRPCClientCredentials returns a credentials.TransportCredentials interface
// suitable for passing to grpc.Dial as an option.
func NewGRPCClientCredentials(serverPubKey, pubKey Pubkey, privKey Privkey) credentials.TransportCredentials {
	return &GRPCCredentials{
		Pub:        serverPubKey,
		ClientPub:  pubKey,
		ClientPriv: privKey,
	}
}

// GRPCCredentials implements credentials.TransportCredentials
type GRPCCredentials struct {
	Pub        Pubkey
	Priv       Privkey
	ClientPub  Pubkey
	ClientPriv Privkey
	// Keystore is a list of public keys we'd expect from clients. This
	// allows a kind of mutual auth
	KeyStore KeyStore
}

// ServerHandshake does the authentication handshake for servers. It returns
// the authenticated connection and the corresponding auth information about
// the connection.
func (g GRPCCredentials) ServerHandshake(rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	longNonce, err := NewLongNonce()
	if err != nil {
		return nil, nil, err
	}

	myNonce := newShortNonce()
	clientNonce := newShortNonce()

	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asServer()
	expectedgreeting.asClient()

	if err := wrc(rawConn, mygreeting[:], theirgreeting[:]); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	if theirgreeting != expectedgreeting {
		return nil, nil, closeAndBail(rawConn, newProtocolError("malformed greeting"))
	}

	var helloCmd helloCommand
	if err := readFrame(rawConn, &helloCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	ephClientPubkey, err := helloCmd.validate(clientNonce, permanentServerPrivkey(g.Priv))
	if err != nil {
		return nil, nil, pE(rawConn, "HELLO", err)
	}

	var welcomeCmd welcomeCommand
	cookieKey, err := welcomeCmd.build(longNonce, ephClientPubkey, permanentServerPrivkey(g.Priv))
	if err != nil {
		return nil, nil, iE(rawConn, "WELCOME", err)
	}
	if err := writeFrame(rawConn, &welcomeCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var initiateCmd initiateCommand
	if err := readFrame(rawConn, &initiateCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	permClientPubKey, ephClientPubkey, ephServerPrivkey, err := initiateCmd.validate(
		clientNonce, permanentServerPubkey(g.Pub), cookieKey)
	if err != nil {
		return nil, nil, pE(rawConn, "INITIATE", err)
	}
	auth := &Authorizer{&EncryptedConn{
		Conn:       rawConn,
		myNonce:    myNonce,
		theirNonce: clientNonce,
		sharedKey:  precomputeKey(Privkey(ephServerPrivkey), Pubkey(ephClientPubkey)),
		isServer:   true,
	}}

	// If we were passed a KeyStore implementation, use it to validate the client's Pubkey.
	if g.KeyStore != nil {
		if !g.KeyStore.Allowed(Pubkey(permClientPubKey)) {
			return nil, nil, errors.New("unauthorized")
		}
	}
	encrypted, err := auth.Allow()
	if err != nil {
		// close rawConn here?
		return nil, nil, closeAndBail(encrypted, err)
	}

	return encrypted, authInfo{}, nil
}

// ClientHandshake does the authentication handshake specified by the corresponding
// authentication protocol on rawConn for clients. It returns the authenticated
// connection and the corresponding auth information about the connection.
func (g GRPCCredentials) ClientHandshake(ctx context.Context, s string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {

	longNonce, err := NewLongNonce()
	if err != nil {
		return nil, nil, err
	}

	myNonce := newShortNonce()
	serverNonce := newShortNonce()

	ephClientPrivkey, ephClientPubkey, err := genEphemeralClientKeyPair()
	if err != nil {
		return nil, nil, closeAndBail(rawConn, newInternalError("cannot generate ephemeral keypair", err))
	}

	var mygreeting, theirgreeting, expectedgreeting greeting
	mygreeting.asClient()
	expectedgreeting.asServer()

	if err := wrc(rawConn, mygreeting[:], theirgreeting[:]); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	if theirgreeting != expectedgreeting {
		return nil, nil, closeAndBail(rawConn, newProtocolError("malformed greeting"))
	}

	var helloCmd helloCommand
	if err := helloCmd.build(myNonce, ephClientPrivkey, ephClientPubkey, permanentServerPubkey(g.Pub)); err != nil {
		return nil, nil, iE(rawConn, "HELLO", err)
	}

	if err := writeFrame(rawConn, &helloCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var welcomeCmd welcomeCommand
	if err := readFrame(rawConn, &welcomeCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	ephServerPubkey, sCookie, err := welcomeCmd.validate(ephClientPrivkey, permanentServerPubkey(g.Pub))
	if err != nil {
		return nil, nil, pE(rawConn, "WELCOME", err)
	}

	var initiateCmd initiateCommand
	if err := initiateCmd.build(myNonce,
		longNonce,
		sCookie,
		permanentClientPrivkey(g.ClientPriv),
		permanentClientPubkey(g.ClientPub),
		permanentServerPubkey(g.Pub),
		ephServerPubkey,
		ephClientPrivkey,
		ephClientPubkey); err != nil {
		return nil, nil, iE(rawConn, "INITIATE", err)
	}

	if err := writeFrame(rawConn, &initiateCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	var genericCmd genericCommand
	if err := readFrame(rawConn, &genericCmd); err != nil {
		return nil, nil, closeAndBail(rawConn, err)
	}

	specificCmd, err := genericCmd.convert()
	if err != nil {
		return nil, nil, pE(rawConn, "READY or ERROR", err)
	}

	sharedKey := precomputeKey(Privkey(ephClientPrivkey), Pubkey(ephServerPubkey))

	switch cmd := specificCmd.(type) {
	case *readyCommand:
		if err := cmd.validate(serverNonce, &sharedKey); err != nil {
			return nil, nil, pE(rawConn, "READY", err)
		}
	case *errorCommand:
		reason, err := cmd.validate()
		if err != nil {
			return nil, nil, pE(rawConn, "ERROR", err)
		}
		return nil, nil, closeAndBail(rawConn, newAuthenticationError(reason))
	default:
		return nil, nil, pE(rawConn, "unknown command", err)
	}

	return &EncryptedConn{
		Conn:       rawConn,
		myNonce:    myNonce,
		theirNonce: serverNonce,
		sharedKey:  sharedKey,
		isServer:   false,
	}, nil, nil
}

// Info provides the ProtocolInfo of this credentials.TransportCredentials
// implementation.
func (g GRPCCredentials) Info() credentials.ProtocolInfo {

	return credentials.ProtocolInfo{}
}

// Clone makes a copy of this TransportCredentials.
func (g GRPCCredentials) Clone() credentials.TransportCredentials {

	return &GRPCCredentials{
		Pub:        g.Pub,
		Priv:       g.Priv,
		ClientPub:  g.ClientPub,
		ClientPriv: g.ClientPriv,
	}
}

// OverrideServerName overrides the server name used to verify the hostname on
// the returned certificates from the server. Our curvetls protocol does not
// have the concept of hostnames or certificates, to we always return nil here.
func (g GRPCCredentials) OverrideServerName(string) error {
	return nil
}

type authInfo struct{}

// AuthType returns our protocol's name as a string.
func (a authInfo) AuthType() string {
	return "curvetls"
}
