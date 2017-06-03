#!/bin/sh -ex

for d in api impl-native-tls impl-openssl tokio-tls-api; do
    (
        cd $d
        cargo package
        cargo publish
    )
done

# vim: set ts=4 sw=4 et:
