curvetls: a simple and robust transport encryption package
==========================================================

Welcome to curvetls.  This package is a Go library that provides a
pluggable wrapper (client / server) for network I/O, which allows
you to upgrade your regular network sockets to a protocol that
supports robust framing and transport security, so long as the
underlying transport is of any reliable kind (e.g. a TCP- or
file-backed `net.Conn`).

The library is documented.  The easiest way to look at the documentation
is by cloning this repository, then running `godoc` against it.

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

Legal information
-----------------

The license of this library is GPLv3 or later.  See file `COPYING`
for details.  For relicensing inquiries, contact the author.

