#!/bin/sh -ex

for d in api tokio-tls-api api-test impl-native-tls impl-openssl impl-rustls impl-stub; do
    (
        cd $d
        cargo publish
    )
done

# vim: set ts=4 sw=4 et:
