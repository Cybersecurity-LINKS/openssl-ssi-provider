/*
 * Copyright 2024 Fondazione LINKS.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.	
 *
 */

# include <openssl/core.h>
# include <openssl/core_dispatch.h>
# include <openssl/crypto.h>
# include "../common/ssi.h"
# include "../common/include/prov/provider_ctx.h"
//#include "../cJSON.h"
#include <string.h>

#define ED25519_SIGSIZE 495 + 1

static OSSL_FUNC_signature_newctx_fn vc_newctx;
static OSSL_FUNC_signature_freectx_fn vc_freectx;

static OSSL_FUNC_signature_digest_sign_init_fn vc_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_fn vc_digest_sign;

static OSSL_FUNC_signature_digest_verify_init_fn vc_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_fn vc_digest_verify;

typedef struct {
    Wallet *w;
    Identity *i;
} VC_SIGN_CTX;

static void *vc_newctx(void *provctx, const char *propq)
{
    VC_SIGN_CTX *ctx;

    ctx = OPENSSL_zalloc(sizeof(VC_SIGN_CTX));
    if (ctx == NULL)
        return NULL;
    
    ctx->w = prov_ctx_get_wallet(provctx); 

    return ctx;
}

static void vc_freectx(void *ctx)
{

    return;
}

int vc_digest_sign_init(void *ctx, const char *mdname,
                                         void *provkey,
                                         const OSSL_PARAM params[]) {
    
    VC_SIGN_CTX *vcctx = (VC_SIGN_CTX *)ctx;

    /* vcctx->i = OPENSSL_zalloc(sizeof(Identity));
    if(vcctx->i == NULL)
        return 0; */

    /* Identity *i = (Identity*)provkey;
    vcctx->i->did = i->did; */

    vcctx->i = (Identity *)provkey;
    return 1;
}

int vc_digest_sign(void *ctx,
                             unsigned char *sigret, size_t *siglen,
                             size_t sigsize, const unsigned char *tbs,
                             size_t tbslen) {
    
    VC_SIGN_CTX *vcctx = (VC_SIGN_CTX *)ctx;
    if(sigret == NULL){
        *siglen = 1000;
        return 1;
    }

    // credential subject
    /* cJSON *payload = cJSON_CreateObject();
    if (payload == NULL)
    {
        return 0;
    }

    cJSON_AddStringToObject(payload, "tbs", tbs);
    char *json_payload = cJSON_Print(payload); */

    printf("tbs: %s\n", (const char *)tbs);
    strcpy(sigret, did_sign(vcctx->w, vcctx->i->did, tbs, tbslen));
    printf("signature from identity: %s\n", sigret);
    *siglen = 1000;

    return 1;
}

int vc_digest_verify_init(void *ctx, const char *mdname,
                                         void *provkey,
                                         const OSSL_PARAM params[]) {
    
    VC_SIGN_CTX *vcctx = (VC_SIGN_CTX *)ctx;

    /* vcctx->i = OPENSSL_zalloc(sizeof(Identity));
    if(vcctx->i == NULL)
        return 0; */

    /* Identity *i = (Identity*)provkey; */

    vcctx->i = (Identity *)provkey;
    char *peer_vc = get_vc(vcctx->i->vc);
    printf("peer vc: %s\n", peer_vc);
    sscanf(peer_vc, "%*s %s", peer_vc);

    vcctx->i->did = vc_verify(vcctx->w, peer_vc);
    if (vcctx->i->did == NULL)
        return 0;
    char *peer_did = get_did(vcctx->i->did);
    sscanf(peer_did, "%*s %*s %s", peer_did);
    printf("peer_did %s\n", peer_did);
    fflush(stdout);

    return 1; 
}

int vc_digest_verify(void *ctx, const unsigned char *sig,
                               size_t siglen, const unsigned char *tbs,
                               size_t tbslen) {
    
    VC_SIGN_CTX *vcctx = (VC_SIGN_CTX *)ctx;

    /* vcctx->i = OPENSSL_zalloc(sizeof(Identity));
    if(vcctx->i == NULL)
        return 0; */

    printf("signature to be verified: %s\n", (const char *)sig);
    fflush(stdout);
    rvalue_t r = did_verify(vcctx->i->did, (const char *)sig);
    if(!r.code)
        return 0;

    return 1;
}

const OSSL_DISPATCH ossl_vc_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))vc_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))vc_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))vc_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT, (void (*)(void))vc_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void)) vc_digest_verify},
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))vc_freectx },
    OSSL_DISPATCH_END
};
