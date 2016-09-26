// Package curvetls is a robust and simple transport encryption library.
//
// Package curvetls provides a pluggable wrapper (client / server)
// for network I/O, which allows you to upgrade your regular network sockets
// to a protocol that supports robust framing and transport security,
// so long as your net.Conn is of any reliable kind (e.g. a TCP- or
// file-backed `net.Conn`).
//
// Usage Instructions
//
// The general implementor's instructions go as follows:
//
// Generate keypairs for clients and server, persisting them to disk if
// you want to, so you can later load them again.
//
// Distribute, however you see fit, the public keys of the server to the
// clients, and the public keys of the clients to the server.
//
// Generate one long nonce per server keypair, and one long nonce per
// client keypair.  You can do this at runtime.
//
// Make your server Listen() on a TCP socket, and Accept() incoming
// connections to obtain one or more server net.Conn.
//
// Make your clients Connect() on a TCP socket to the Listen() address
// of the server.
//
// Right after Connect() on your client, wrap the net.Conn you received
// by using WrapClient() on that client net.Conn, and giving it the client
// keypair, its corresponding client long nonce, and the server public key.
//
// Right after Accept() on your server, wrap the net.Conn you received
// by using WrapServer() on that server net.Conn, and giving it
// the server keypair together with its corresponding server long nonce.
//
// Use the public key that WrapServer() collects to decide whether to
// Allow() the returned EncryptedConn or Deny() it.
//
// Congratulations, at this point you have a connection between peers that
// is encrypted with (a limited version of) the CurveZMQ protocol.
//
// Sending and receiving traffic is covered by the documentation of the
// Read(), ReadFrame() and Write() methods of EncryptedConn.  Two
// example programs are included in the cmd/ directory of this package.
package curvetls
