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

#include "endecoder_local.h"

int read_der(PROV_CTX *provctx, OSSL_CORE_BIO *cin,  char **data,
                  long *len) 
{
    int ok;
    unsigned char *d = malloc(2000);
    size_t l = 0;
    
    BIO *in = ossl_bio_new_from_core_bio(provctx, cin);
    if (in == NULL)
        return 0;
    ok = BIO_read_ex(in, d, 2000, &l);
    if (ok) {
        d[l] = '\0';
        *data = d;
        //printf("%s\n", *data);
        *len = l;
    }
    BIO_free(in);
    return ok;      
}