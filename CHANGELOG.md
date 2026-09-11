# Changelog

All notable changes to OSIVault will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial repository bootstrap and package structure.
- Implementation of `osivault.audit` merged audit module featuring HMAC-SHA-256 signatures, previous-hash chaining, self-describing envelopes, key rotation, and immutability guards.
- Interface stubs for `osivault.fields`, `osivault.sign`, `osivault.tokens`, `osivault.auth`, and `osivault.watch`.
