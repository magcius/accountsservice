#!/bin/sh

(cd $(dirname $0);
 autoreconf --install --force --symlink &&
 intltoolize --force &&
 autoreconf --force &&
 ./configure $@)
