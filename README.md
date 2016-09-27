curvetls: a simple, robust transport encryption package
=======================================================

curvetls is a Go library that gives you a robust framing and encryption
layer for your Go programs, striving to be secure, strict, and simple.

With curvetls, it's dead easy to go from raw sockets to secure channels,
based on CurveCP (NaCL) encryption primitives, and you get framing for free.
This makes it dead easy for you to write secure, robust clients and servers
that do not need to implement low-level control flow at all.  While curvetls
is based on the CurveZMQ specification, it does not depend on any ZeroMQ
or CurveZMQ libraries itself.

This library gives you a layered, stackable wrapper (client / server) for
network I/O, which allows you to upgrade regular network sockets to the
curvetls protocol.  All the wrapper needs is a key pair, a random nonce,
and a socket whose underlying transport is of any reliable kind (e.g.
a TCP- or file-backed `net.Conn`).

The library is documented.  The easiest way to look at the documentation
is by cloning this repository, then running `godoc` against it.
Alternatively, the documentation for the latest version of the `master`
branch of this repository can be browsed at
https://godoc.org/github.com/Rudd-O/curvetls just fine.

Test client programs
--------------------

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

Quality, testing and benchmarking
---------------------------------

To run the tests:

        make test

To run a variety of benchmarks (such as message encryption and decryption):

        make bench

curvetls releases should not come with failing tests.  If a test fails,
that is a problem and you should report it as an issue right away.

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

Technical and compatibility information
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

Legal information
-----------------

The license of this library is GPLv3 or later.  See file `COPYING`
for details.  For relicensing inquiries, contact the author.
