#!/bin/sh

set -e

autoheader &
aclocal
autoconf
wait
