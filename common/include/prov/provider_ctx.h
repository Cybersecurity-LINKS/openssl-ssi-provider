#ifndef PROV_CTX_H
# define PROV_CTX_H

# include <openssl/types.h>
# include <openssl/crypto.h>
# include <openssl/bio.h>
# include <openssl/core.h>
#include "/home/pirug/Desktop/identity-cbindings/header-binding/identity.h"

typedef struct prov_ctx_st {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;         /* For all provider modules */
    BIO_METHOD *corebiometh;
    Wallet *w;
} PROV_CTX;

PROV_CTX *ossl_prov_ctx_new(void);
void ossl_prov_ctx_free(PROV_CTX *ctx);
void ossl_prov_ctx_set0_libctx(PROV_CTX *ctx, OSSL_LIB_CTX *libctx);
void ossl_prov_ctx_set0_handle(PROV_CTX *ctx, const OSSL_CORE_HANDLE *handle);
void ossl_prov_ctx_set0_core_bio_method(PROV_CTX *ctx, BIO_METHOD *corebiometh);
OSSL_LIB_CTX *ossl_prov_ctx_get0_libctx(PROV_CTX *ctx);
const OSSL_CORE_HANDLE *ossl_prov_ctx_get0_handle(PROV_CTX *ctx);
BIO_METHOD *ossl_prov_ctx_get0_core_bio_method(PROV_CTX *ctx);

Wallet *prov_init_wallet(void);
void prov_ctx_set_wallet(PROV_CTX *ctx, Wallet *w);
Wallet *prov_ctx_get_wallet(PROV_CTX *ctx);

#endif