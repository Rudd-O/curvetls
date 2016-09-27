// Package curvetls is a simple, robust transport encryption library.
//
// This is a pluggable wrapper (client / server) for network I/O, which
// allows you to upgrade your regular network sockets to a protocol that
// supports robust framing, transport security and authentication,
// so long as your net.Conn is of any reliable kind (e.g. a TCP- or
// file-backed net.Conn).
//
// Usage Instructions
//
// (a) Generate keypairs for clients and server, persisting them to disk if
// you want to, so you can later load them again.
//
// (b) Distribute, however you see fit, the public keys of the server to the
// clients, and the public keys of the clients to the server.
//
// (c) Generate one long nonce per server keypair, and one long nonce per
// client keypair.  You can do this at runtime.  Never reuse the
// same long nonce for two different keypairs.
//
// (d) Make your server Listen() on a TCP socket, and Accept() incoming
// connections to obtain one or more server net.Conn.
//
// (e) Make your clients Connect() on a TCP socket to the Listen() address
// of the server.
//
// (f) On your client, right after Connect(), wrap the net.Conn you received
// by using WrapClient() on that client net.Conn, and giving it the client
// keypair, its corresponding client long nonce, and the server public key.
// WrapClient() will return an encrypted socket you can use to talk to
// the server.
//
// (g) On your server, right after Accept(), wrap the net.Conn you received
// by using WrapServer() on that server net.Conn, and giving it
// the server keypair together with its corresponding server long nonce.
// Use the authorizer and the public key that WrapServer() returns to
// decide whether to call Allow() or Deny() on the authorizer.  Allow()
// will return an encrypted socket you can use to talk to the client.
//
// Congratulations, at this point you have a connection between peers that
// is encrypted with (a limited version of) the CurveZMQ protocol.
//
// Sending and receiving traffic is covered by the documentation of the
// Read(), ReadFrame() and Write() methods of EncryptedConn.  Two
// example programs are included in the cmd/ directory of this package.
package curvetls
