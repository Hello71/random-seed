#!/bin/sh
# SPDX-License-Identifier: BSD-3-Clause

set -e

autoheader &
aclocal -I m4 --install
autoconf

wait
