The random-seed format consists of:

1. 512 bytes of random seed data for compatibility with other random seed
   implementations
2. The magic string "RANDOM SEED FILE VERSION 1".
3. A series of line delimited commands with space delimited arguments.

Comments are not supported.

# Hashing
In an attempt to improve privacy, device IDs are hashed with SHA256(random-data
|| ID) where || denotes concatenation and random-data is the 512 bytes of
random data at the start of the file.

# Commands

## salt
Set the salt for the following commands to the argument.  This must be the
first command.

## machine-id
Check that the contents of `/etc/machine-id`, when hashed, matches the
argument.

## fs-id
Check that calling statfs(2) on the random seed file returns a `f_fsid` that
when hashed, matches the argument.

## fs-uuid
Check that the UUID of the random seed file system, when hashed as a string,
matches the argument.

## drive-id
Check that the ID as determined by udev of the random seed file system, when
hashed as a string, matches the argument.

## done
End of mandatory commands.
