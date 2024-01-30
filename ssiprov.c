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
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/bio.h>
#include "names.h"
#include "implementations.h"
#include "common/include/prov/bio.h"

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

static const OSSL_ALGORITHM ssi_keymgmt[] = {
    { PROV_NAMES_VC , "provider=ssi", ossl_vc_keymgmt_functions },
    { PROV_NAMES_DID, "provider=ssi", ossl_did_keymgmt_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ssi_encoder[] = {
    { PROV_NAMES_VC , "provider=ssi,output=pem,structure=SubjectPublicKeyInfo", ossl_vc_to_SubjectPublicKeyInfo_pem_encoder_functions },
    { PROV_NAMES_VC , "provider=ssi,output=pem,structure=PrivateKeyInfo", ossl_vc_to_PrivateKeyInfo_pem_encoder_functions },
    { PROV_NAMES_VC , "provider=ssi,output=der,structure=SubjectPublicKeyInfo", ossl_vc_to_SubjectPublicKeyInfo_der_encoder_functions },
    /* { PROV_NAMES_DID, "provider=ssi,output=pem,structure=PrivateKeyInfo", ossl_did_to_PrivateKeyInfo_pem_encoder_functions }, */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ssi_decoder[] = {
    { PROV_NAMES_VC, "provider=ssi,input=der,structure=SubjectPublicKeyInfo", ossl_SubjectPublicKeyInfo_der_to_vc_decoder_functions },
    { PROV_NAMES_VC, "provider=ssi,input=der,structure=PrivateKeyInfo", ossl_PrivateKeyInfo_der_to_vc_decoder_functions },
    /* { PROV_NAMES_DID, "provider=ssi,input=der,structure=PrivateKeyInfo", ossl_PrivateKeyInfo_der_to_did_decoder_functions }, */
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM ssi_signature[] = {
    { PROV_NAMES_VC, "provider=ssi", ossl_vc_signature_functions},
    { NULL, NULL, NULL}
};

static const OSSL_PARAM ssi_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ssi_gettable_params(void *provctx)
{
    return ssi_param_types;
}

static int ssi_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "SSI provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "1"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OPENSSL_FULL_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) /* always in running state */
        return 0;

    return 1;
}

static const OSSL_ALGORITHM *ssi_query(void *provctx, int operation_id,
                                         int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_KEYMGMT:
        return ssi_keymgmt;
    case OSSL_OP_ENCODER:
        return ssi_encoder;
    case OSSL_OP_DECODER:
        return ssi_decoder;
    case OSSL_OP_SIGNATURE:
        return ssi_signature;
    }
    return NULL;
}

static void ssi_teardown(void *provctx)
{   
    //TODO (have a look at dflt-prov)
}

static const OSSL_DISPATCH ssi_dispatch_table[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))ssi_teardown },
    { OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))ssi_gettable_params },
    { OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))ssi_get_params },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))ssi_query },
    OSSL_DISPATCH_END
};

// OSSL_provider_init_fn ossl_ssi_provider_init;

extern int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                            const OSSL_DISPATCH *in, const OSSL_DISPATCH **out,
                            void **provctx) {
    
    OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;
    BIO_METHOD *corebiometh;
    Wallet *w;

    if (!ossl_prov_bio_from_dispatch(in))
        return 0;
    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_GET_LIBCTX:
            c_get_libctx = OSSL_FUNC_core_get_libctx(in);
            break;
        default:
            /* Just ignore anything we don't understand */
            break;
        }
    }

    if (c_get_libctx == NULL)
        return 0;

    /*
     * We want to make sure that all calls from this provider that requires
     * a library context use the same context as the one used to call our
     * functions.  We do that by passing it along in the provider context.
     *
     * This only works for built-in providers.  Most providers should
     * create their own library context.
     */
    if ((*provctx = ossl_prov_ctx_new()) == NULL
            || (corebiometh = ossl_bio_prov_init_bio_method()) == NULL
            || (w = prov_init_wallet()) == NULL ) {
        ossl_prov_ctx_free(*provctx);
        *provctx = NULL;
        return 0;
    }
    ossl_prov_ctx_set0_libctx(*provctx,
                                       (OSSL_LIB_CTX *)c_get_libctx(handle));
    ossl_prov_ctx_set0_handle(*provctx, handle);
    ossl_prov_ctx_set0_core_bio_method(*provctx, corebiometh);
    prov_ctx_set_wallet(*provctx, w);

    *out = ssi_dispatch_table;

    return 1;
}