This is an attempt to document the random seed behavior of different operating
systems. This is based mostly on Goog^WInternet searches. If you believe this
information is incorrect, please submit patches.

## Linux

The random seed behavior of Linux is well documented, but we will rehash it
(heh) here for completeness. Linux has three interfaces for random access:
/dev/random, /dev/urandom, and getrandom. /dev/random attempts to keep track of
the entropy count and blocks when it reaches zero. /dev/urandom never blocks.
getrandom blocks during early startup until the entropy count becomes "full".

## OpenBSD

OpenBSD has one central RNG for all its randomness. The bootloader seeds the
RNG using random data from installation plus random data obtained from the
OpenBSD servers. Therefore, none of the random interfaces ever block.

## FreeBSD

On FreeBSD, /dev/random and /dev/urandom both block until the random seed is
installed. This is defined as the time when a FD opened read-write on
/dev/random is closed. Thereafter, they do not block.

## Windows

The exact behavior of the Windows RNG is not publicly documented. It is,
however, known to be seeded in part by a registry value.

## Mac OS

Dunno. https://github.com/jedisct1/libsodium/issues/594 says the PRNG is
terrible, then says it's "totally fine". I don't have Mac, and the Mac man
pages are shamefully not accessible online, so I cannot check for myself.
