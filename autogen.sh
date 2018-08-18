#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause

set -e

{ ${AUTOHEADER:-autoheader} && touch config.h; } &
${ACLOCAL:-aclocal} -I m4 --install && touch aclocal.m4
${AUTOCONF:-autoconf} && touch configure

wait
