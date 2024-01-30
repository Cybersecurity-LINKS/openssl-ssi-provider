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

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_object.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "../common/include/prov/bio.h"
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <string.h>
#include "../names.h"

static OSSL_FUNC_decoder_newctx_fn der2did_newctx;
static OSSL_FUNC_decoder_freectx_fn der2did_freectx;
static OSSL_FUNC_decoder_decode_fn PrivateKeyInfo_der_to_did_decode;

struct der2did_ctx_st {
    PROV_CTX *provctx;
};

static int read_did(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  char **did_doc,
                  long *did_doc_len)
{
    int ok;
    char *data = malloc(2000);
    size_t length = 0;
    
    BIO *in = ossl_bio_new_from_core_bio(provctx, cin);
    if (in == NULL)
        return 0;
    ok = BIO_read_ex(in, data, 2000, &length);
    if (ok) {
        *did_doc = data;
        //printf("%s\n", *did_doc);
        *did_doc_len = length;
        /* OPENSSL_free(mem); */
    }
    BIO_free(in);
    return ok;
} 

static void *der2did_newctx(void *provctx)
{
    /* printf("DID DECODER ctx new\n"); */
    struct der2did_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
    }

    return ctx;
}

static void der2did_freectx(void *vctx)
{
    struct der2did_ctx_st *ctx = vctx;
    OPENSSL_free(ctx);
}

static int PrivateKeyInfo_der_to_did_decode(void *vctx, OSSL_CORE_BIO *cin, int selection,
                          OSSL_CALLBACK *data_cb, void *data_cbarg,
                          OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct der2did_ctx_st *ctx = vctx;
    char *did_doc = NULL;
    long did_doc_read = 0;
    int ok = 0;
    char oid[20];

    ok = read_did(ctx->provctx, cin, &did_doc, &did_doc_read);
    if(!ok)
        return ok;

    if(sscanf(did_doc, "%s %s", oid, did_doc) == EOF)
    	return 0;

    ok = OPENSSL_strcasecmp(oid, DID_OID);
    if(ok)
        return 0;

    OSSL_PARAM params[4];
    int object_type = OSSL_OBJECT_PKEY;

    params[0] =
        OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE, &object_type);
    params[1] = 
        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                             "DID", 0);
    params[2] =
        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE, did_doc, strlen(did_doc));

    params[3] = OSSL_PARAM_construct_end();

    ok = data_cb(params, data_cbarg);

    OPENSSL_free(did_doc);
    return ok;
}

const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_did_decoder_functions[] = {           
        { OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))der2did_newctx },                                 
        { OSSL_FUNC_DECODER_FREECTX, (void (*)(void))der2did_freectx },
        { OSSL_FUNC_DECODER_DECODE, (void (*)(void))PrivateKeyInfo_der_to_did_decode },           
        OSSL_DISPATCH_END
};
