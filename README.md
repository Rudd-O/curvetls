# curvetls: a simple, robust transport encryption package

curvetls is a Go library that gives you a robust framing and encryption
layer for your Go programs, striving to be secure, strict, and simple.

With curvetls, it's dead easy to go from ordinary sockets to secure
encrypted channels that support framing.  This makes it trivial for you
to write secure, robust clients and servers that do not need to implement
low-level control flow.  curvetls does not use large or unproven libraries,
avoids unsafe C bindings, follows well-documented specifications, practices
well-understood cryptography, and avoids placing undue trust in peers,
even authenticated ones.

This library gives you a layered, stackable wrapper (client / server) for
network I/O, which allows you to upgrade regular network sockets to the
curvetls protocol.  All the wrapper needs is a key pair, a random nonce,
and a socket whose underlying transport is of any reliable kind (e.g.
a TCP- or file-backed `net.Conn`).

curvetls is documented with developers' interests in mind.
[Take a look at the documentation online](https://godoc.org/github.com/Rudd-O/curvetls).
Alternatively, clone this repository, then run `godoc` against it.

## Features

* Simple and robust
  [elliptic curve encryption](https://godoc.org/golang.org/x/crypto/nacl/box)
  of communications between peers.
* Well-defined, robust framing scheme for reliable delivery of whole messages,
  based on the
  [ZeroMQ ZMTP specification](https://rfc.zeromq.org/spec:37/ZMTP/).
* Robust public key authentication scheme to let servers decide which clients
  are authorized to proceed, based on the
  [CurveZMQ spec](https://rfc.zeromq.org/spec:37/ZMTP/).
* Straightforward use of the library in your network clients and servers.

## Test client programs

In addition to the library, this project ships three demon programs,
which can show you how to use the library:

* `curvetls-genkeypair` generates keypairs for the use of the other
  command-line programs
* `curvetls-server` implements a test ping-pong server
* `curvetls-client` implements a test ping-pong client

To run these programs, you can simply compile the library after
cloning it to the local directory:

        [user@host ~]$ cd /path/to/curvetls
        [user@host curvetls]$ make
        [user@host curvetls]$ 

Generate some key pairs:

        [user@host curvetls]$ bin/curvetls-genkeypair  # note these for the server
        Private key: pT6GGmPNgSPsGKD8UTPdVN50xOGeZr+eb53gfAYoeVm4=
        Public key:  Puwo38S2npQijFuh5cuShYpTnQ+ZupkwveS/A1HjjkSY=
        Tip:         Both keys are encoded in base64 format with a one-character key type prefix
        [user@host curvetls]$ bin/curvetls-genkeypair  # note these for the client
        Private key: paICEhaq2fBJkCRoIMbncQ2sv+LolEvjgM43DYcrQpqM=
        Public key:  Pr59DbWYjUHlj0Z8kAY9LUyP/8hUi5kC+ByX6xvPKIwc=
        Tip:         Both keys are encoded in base64 format with a one-character key type prefix
        [user@host curvetls]$ 

Run the server (in the background):

        [user@host curvetls]$ bin/curvetls-server 127.0.0.1:9001 \
            pT6GGmPNgSPsGKD8UTPdVN50xOGeZr+eb53gfAYoeVm4= \
            Puwo38S2npQijFuh5cuShYpTnQ+ZupkwveS/A1HjjkSY= \
            Pr59DbWYjUHlj0Z8kAY9LUyP/8hUi5kC+ByX6xvPKIwc= &

Run the client:

        [user@host curvetls]$ bin/curvetls-client 127.0.0.1:9001 \
            paICEhaq2fBJkCRoIMbncQ2sv+LolEvjgM43DYcrQpqM= \
            Pr59DbWYjUHlj0Z8kAY9LUyP/8hUi5kC+ByX6xvPKIwc= \
            Puwo38S2npQijFuh5cuShYpTnQ+ZupkwveS/A1HjjkSY=

And see the ping-pong happen.  The server will exit as soon as it is
done with the first connection.

Feel free to Wireshark the programs as
they execute, to verify that data is, in fact, being encrypted as it
goes from program to program.

Run the programs with no arguments to get usage information.

## Quality, testing and benchmarking

To run the tests:

        make test

To run a variety of benchmarks (such as message encryption and decryption):

        make bench

curvetls releases should not come with failing tests.  If a test fails,
that is a problem and you should report it as an issue right away.

## Goals and motivations

As security software, curvetls has the following goals:

* To enable users of this library to depend on as little code as possible,
  with special emphasis on reducing unsafe code.
* To give implementors a simple way to enable encryption between two peers,
  with as little effort as possible.
* To make sure that implementors do not have to deal with any low-level
  details that they may screw up, compromising the security of their programs.
* To ensure that users of this library do not have to deal with hidden
  surprises, such as servers allowing clients to allocate unbound resources.

curvetls focuses on getting the low-level security details right, so that
you do not have to.

### Why curvetls instead of `net.tls`?

Some people have asked why this library needs to exist, given that Go has
`net/tls`, which is a high-performance crypto library.

The answer is that `net/tls` is much, much more than just a crypto library,
and that has implications for security and complexity.  There's a niche in
communications where TLS is overkill but plain TCP is irresponsible, and
that is a niche which many packages have attempted to fill, from CurveCP
to tcpcrypt.  curvetls fills this niche quite nicely.

The list-form, practical answer to why you may want to avoid `net/tls`:

* A PKI system with certificates imposes on the implementor the additional
  burden of having to manage the certificate authority that emits the
  certificates, possibly a revocation infrastructure, both for clients and
  servers.
* PKI as implemented in the modern world, including in `net/tls`, is a
  bit of a mess in that you have to write extra code if you want to do
  something that's outside the norm, but still perfectly sensible for certain
  use cases.  Like, say, have clients reject certificates not signed by
  VeriSign, or have full cert validation without domain name validation.
  This demands configuration code that you *must* get right in your program.
* X.509 certificates are very complex compared to simple base64
  strings (what this library uses).  There have been vulnerabilities,
  sometimes years-old, in certificate parsing code.
* TLS itself is highly complex, because of backwards compatibility reasons
  and the need to support many ciphers.  This complexity has given rise to
  many security issues as well as many opportunities for the implementor
  to shoot himself on the foot.  This is 100% unneeded complexity if all you
  want is to send / receive well-encrypted data between two private peers.

TLS is fine and dandy, very well supported in Go via the `net/tls` package,
and many use cases effectively require you to use TLS.  However, TLS brings
in a *lot* more complexity than just handshake plus NaCL encryption, and
that increases the attack surface.  Sometimes all you need is a simple
drop-in implementation of peer-to-peer public key crypto.  That's what
curvetls aims to do well.  I think four lines of (non-error handling) code
— one for creating a keypair, one for creating a nonce, one for driving
the handshake, and one for authorizing the client — is as simple as it can
get, and the code that runs underneath is far less complex than anything
you get with invoking any of `net.tls` for the same use case.

### Why are you rolling your own crypto code / protocol?

Let's be 100% blunt: curvetls does *not* roll its own crypto.  The crypto
in curvetls is the same crypto as the NaCL library, which is fast,
well-tested and presumed to be strong.

curvetls also does *not* roll its own protocol.  One of the goals of curvetls
is to be interoperable with CurveZMQ DEALER sockets in reliable mode
(e.g. TCP).  As such, we implement the pertinent specification, which are
very good specifications — 100% unambiguous — and enjoy many implementations
from competing entities.

curvetls users also enjoy the client / server handshake and send / receive
framing that is the great work of the ZeroMQ folks (to my knowledge,
primarily Pieter Hintjens).  In practical terms, this means you, as a user
of curvetls, do not have to worry about authentication / authorization
state machines or incomplete messages.  A peer is either authorized or not.
A message is either fully-received or not.

### Why not CurveZMQ instead?

ZeroMQ is great software, but it has three problems, one Go-specific and
two more in general w.r.t. security:

**Problem numero uno**: you can't really send on a ZeroMQ socket in a
goroutine while receiving on that same socket in another goroutine.
[Your program will crash if you do](https://github.com/pebbe/zmq3/issues/21#issuecomment-68414300).
This is fundamental if you want to have a program that sends and
receives at the same time, without having to "take turns", HTTP style.
There's ways you can get around that —
[PAIR inproc socket pairs](http://stackoverflow.com/questions/36437799/how-to-deal-with-zmq-sockets-lack-of-thread-safety)
for in-process communication, pairs of DEALER sockets on each peer,
[poll loops and reactors](https://stackoverflow.com/a/36438543) — but all
of these ways impose extra complexity and a very unnatural and non-idiomatic
programming regime for Go programs.

curvetls sockets, in contrast, are safe to `Read()` from one goroutine
while another goroutine `Write()`s to them.  They work in the expected manner
and do not require you to implement any bespoke multiplexing solutions.

**Problem numero dos**: if you use the existing ZeroMQ implementations,
then you are bringing into your process a lot of unsafe code, plus a lot
of code you don't need just to do peer-to-peer encryption and authentication.

curvetls effectively implements the most basic use case of ZeroMQ plus
CurveZMQ, without the extra dependency of ZeroMQ, or any unsafe C code.
This package depends on no unsafe libraries, beyond perhaps the Go NaCL
implementation or the Go standard library itself.

**Problem numero tres**: did you know that ZeroMQ happily lets clients
send 1 GB buffers, and allocates that memory on the server to receive
them?

We have a high-priority item on our roadmap which involves giving
implementors a knob that lets them limit the amount of memory a single frame
can consume.  Because in ZeroMQ a frame can be effectively as large as you
can imagine, and the frame will not be delivered to the peer until the
peer has read all of it into memory, malicious clients which have
successfully completed the handshake — perhaps they stole a keypair,
perhaps the server `Allow`()s all peers — can bring a server down by making
it allocate inordinately large amounts of memory.

Additionally, curvetls — unlike CurveZMQ — will not accept any metadata
from a peer during the handshake (which happens *before* the peer has been
authenticated).  CurveZMQ metadata is effectively specified to be as big as
you can imagine, which lets clients (and servers!) fill memory on your
server before the CurveZMQ handshake completes.  On the roadmap we have
an item which involves adding support for metadata during handshake, but
not before we can provide you, the implementor, with a knob that limits
the amount of metadata a peer is allowed to send.

**Problem numero cuatro**: ZeroMQ happily accepts as many connections as peers,
including hostile peers, will send its way.  You are not in control of the
`Accept()` call — your code only gets notified of *messages*, not of
peer connections and disconnections.  These are some odd socket semantics
which work well in many use cases that involve trustworthy peers, but
these semantics work badly outside of it.  Additionally, you have to write
extra code in order to track identities — ZeroMQ will not, by default,
let you track of peers by key identity, mostly assuming that a message is a
message is a message, irrespective of which peer is sending it.  Effectively,
you have reduced control over the low-level connection and authentication
process, when you implement a ZeroMQ server.  You *can* solve the
authentication and authorization issue, but the low-level connection
acceptance and throttling part is strictly off-limits to you as a programmer.

In curvetls, you are in charge of connecting / listening / accepting /
tracking / closing sockets.  This lets you implement custom throttling
policies based on which peer is connecting *prior* to the handshake itself,
and it lets you know verifiably which peer has connected as soon as the
handshake is over.  You *want* these properties when writing robust servers.
Have a traffic storm or more clients than your program wants to handle?
Throttle the socket `Accept()`.  Have a peer that is already active and
authenticated but wants to connect for a second time?  Close the socket
on it as soon as the handshake is over.  Have a peer that is relentlessly
connecting when you don't want it to?  Close the socket on it as soon as
the `Accept()` returns, or run a firewall rule change — you have the peer's
IP address right after `Accept()`, after all.

These were the security concerns I needed to address when I set out to write
curvetls, and I'm happy to report they have either been addressed or been
considered high-priority and active work.

### Why not CurveCP?

The first reason is that there are no complete implementations of CurveCP
for Go.  You can take the existing implementation and write a binding for it,
but that was much more work than implementing a well-documented specification
in a memory-safe language.

The second reason is that, even if you do a binding to CurveCP, the full power
of the CurveCP security mechanism would then be available to implementors
but with the burden of having to rely on unsafe code that is basically
abandoned.

The third reason: CurveCP brings with it the extra code of implementing a
reliable protocol over UDP.  This aspect of CurveCP is truly a noble project
that can revolutionize the Internet — if it hasn't already, as CurveCP was
the forefather of Google's QUIC — but it's still extra code that is less
tested than TCP, and it puts more complexity in the path between peer and
your program's processing code.

### Why not (this thing I haven't heard of)?

I'm happy to read the code of that thing and talk to you about it.  Who knows,
maybe that thing will render curvetls entirely unnecessary?

## Technical and compatibility information

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

## Legal information

The license of this library is GPLv3 or later.  See file `COPYING`
for details.  For relicensing inquiries, contact the author.
