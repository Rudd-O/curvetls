/* Package curvetls provides a pluggable wrapper (client / server)
for network I/O, which allows you to upgrade your regular network sockets
to a protocol that supports robust framing and transport security,
so long as your net.Conn is of any reliable kind (e.g. a TCP- or
file-backed `net.Conn`).

Usage instructions
------------------

The general implementor's instructions go as follows:

* Generate keypairs for clients and server, persisting them to disk if
  you want to, so you can later load them again.
* Distribute, however you see fit, the public keys of the server to the
  clients, and the public keys of the clients to the server.
* Generate one long nonce per server keypair, and one long nonce per
  client keypair.  You can do this at runtime.
* Make your server Listen() on a TCP socket, and Accept() incoming
  connections to obtain one or more server net.Conn.
* Make your clients Connect() on a TCP socket to the Listen() address
  of the server.
* Right after Connect() on your client, wrap the net.Conn you received
  by using WrapClient() on that client net.Conn, and giving it the client
  keypair, its corresponding client long nonce, and the server public key.
* Right after Accept() on your server, wrap the net.Conn you received
  by using WrapServer() on that server net.Conn, and giving it
  the server keypair together with its corresponding server long nonce.
* Use the public key that WrapServer() collects to decide whether to
  Allow() the returned EncryptedConn or Deny() it.

Congratulations, at this point you have a connection between peers that
is encrypted with (a limited version of) the CurveZMQ protocol.

Goals and motivations
---------------------

One of the goals of curvetls is to be interoperable with CurveZMQ DEALER
sockets in reliable mode (e.g. TCP), but without the odd socket semantics of
ZeroMQ, which give you little control over the low-level connection and
acceptance process, and make it hard to track peer identities.

In curvetls, you are in charge of connecting / listening / accepting /
tracking / closing sockets, rather than letting ZeroMQ handle that behind the
scenes.  This lets you implement custom access control mechanisms and early
connection throttling, which is desirable when writing robust servers.

Of course, another goal of curvetls is to make sure that the full power of the
CurveCP security mechanism is available to you without needing to rely on
the extra dependency of ZeroMQ, or any unsafe C code.

As such, this package uses no unsafe libraries or dependencies like ZeroMQ,
however, the client / server handshake and send / receive mechanisms reuse the
great work that is the ZeroMQ framing scheme.  In practical terms, this means
you do not have to worry about receiving incomplete messages.

Technical / compatibility information
-------------------------------------

Compatibility:

* The robust framing is compliant with the ZeroMQ framing scheme as documented
  in https://rfc.zeromq.org/spec:37/ZMTP/
* The transport security handshake is compliant with the CurveZMQ specification
  as documented in available at http://curvezmq.org/

Any deviations from the CurveZMQ handshake specification, or interoperability
problems with CurveZMQ implementations, as well as deviations and problems
from / with the ZeroMQ framing scheme, are bugs.  You should report them,
so we can fix them.

Note that, if you choose to use unreliable transports such as UDP, you must
roll your own congestion and retransmission features on each net.Conn you
intend to wrap.  Perhaps the right way to go about it, is to write a similar
wrapping library which will wrap (let's say, UDP) network I/O sockets using
the CurveCP congestion algorithm as specified in its documentation.  Such a
wrapper, if it returns net.Conn instances, will be compatible with this work.
*/

package curvetls
