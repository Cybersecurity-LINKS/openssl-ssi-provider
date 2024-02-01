# Self-Sovreign Identity (SSI) provider for OpenSSL-3.x

This repository enables the creation and management of Verifiable Credentials and Decentralized Identifiers in OpenSSL. We handle them as if they were the components of an asymmetric keypair. In details, the VC is the public part and the DID Document is the private part.

In our implementation VCs and DIDs are handled by the [identity](https://github.com/iotaledger/identity.rs) library developed by the IOTA Foundation. DID documents are stored on the IOTA Tangle.

The provider can be extendend to support other distributed ledger

## Build and Install

Have a look at the [INSTALL](./INSTALL.md) file to build and install the provider.
