# Changelog

## [Unreleased]

## [0.6.0] - 2021-10-24

- **Edit: was not updated, in this version it is still 0.19** [Upgrade to rustls 0.20](https://github.com/stepancheg/rust-tls-api/pull/39)
- Use `anyhow` and `thiserror` crates for errors

## [0.5.0] - 2021-02-21

- `async-std` support added
- `security-framework` is implemented natively
- update all dependencies to the latest versions
- more tests, more features, more everything

## [0.4.0] - 2020-05-17

- Upgrade rustls dependency to 0.17.0

## [0.3.2] - 2020-01-03

- Make futures returned from `connect` and `accept` `Send`

## [0.3.1] - 2020-01-02

- Remove unused dependency on `futures` crate

## [0.3.0] - 2020-01-02

- Upgraded to tokio 0.2
- Tokio is unconditional dependency now (and API is async only now)

## [0.2.1] - 2020-01-01

- Start of changelog
