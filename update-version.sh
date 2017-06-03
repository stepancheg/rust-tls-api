#!/bin/sh -e

version="0.1.3"

sed -e 's,^version = .*,version = "'$version'",' -i '' \
    */Cargo.toml

sed -e '/^tls-api.*path/ s,version = [^ ]*",version = "'$version'",' -i '' */Cargo.toml

# vim: set ts=4 sw=4 et:
