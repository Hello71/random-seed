#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause

set -e -x

${AUTOHEADER:-autoheader} -f &
${ACLOCAL:-aclocal} -I m4 --force --install
${AUTOCONF:-autoconf} -i -f

wait
