#!/bin/sh -ex

for d in api api-test impl-native-tls impl-openssl impl-rustls impl-stub tokio-tls-api; do
    (
        cd $d
        cargo package
        cargo publish
    )
done

# vim: set ts=4 sw=4 et:
