#!/bin/sh

(cd $(dirname $0);
 autoreconf --install --force --symlink --verbose &&
 intltoolize --force &&
 autoreconf --force --verbose &&
 ./configure $@)
