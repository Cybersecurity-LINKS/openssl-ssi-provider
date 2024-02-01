# Build and Install on Unix/Linux/macOS

## Prerequisites

### OpenSSL

Download and install locally our modified version of OpenSSL that supports VC certificate type which is a fork of the original OpenSSL repo

    git@github.com:Cybersecurity-LINKS/openssl.git

### identity-cbindings

Download and install locally identity-cbindings library that will generate C interfaces the provider can interact with to manage DIDs and VCs.

    git@github.com:Cybersecurity-LINKS/identity-cbindings.git

Move the file in `identity-cbindings/bindings-demo/identity.h` in `openssl-ssi-provider/common/include/prov/`.  

## Build & Install

    cd path/to/openssl-ssi-provider

Edit the `Makefile` by specifying the right paths for `OPENSLL_INSTALL_DIR`,`IDENTITY_CBINDINGS`,`OPENSSL_LIB`. OPENSSL_LIB must be set to lib in a 32-bit OS or lib64 in a 64-bit OS. Then  

    make
    make install

`ssi.so` will be installed in `$OPENSSL_INSTALL_DIR/$OPENSSL_LIB/ossl-modules`
