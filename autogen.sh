#!/bin/sh

ACLOCAL="aclocal $ACLOCAL_FLAGS"
export ACLOCAL

(cd $(dirname $0);
 autoreconf --install --force --symlink --verbose &&
 intltoolize --force &&
 autoreconf --force --verbose &&
 ./configure $@)
