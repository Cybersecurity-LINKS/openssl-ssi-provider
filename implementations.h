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

/* OP_KEYMGMT */
extern const OSSL_DISPATCH ossl_vc_keymgmt_functions[];
extern const OSSL_DISPATCH ossl_did_keymgmt_functions[];

/* OP_ENCODER */
extern const OSSL_DISPATCH ossl_vc_to_PrivateKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH ossl_vc_to_SubjectPublicKeyInfo_pem_encoder_functions[];
extern const OSSL_DISPATCH ossl_vc_to_SubjectPublicKeyInfo_der_encoder_functions[];
extern const OSSL_DISPATCH ossl_did_to_PrivateKeyInfo_pem_encoder_functions[];

/* OP_DECODER */
extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_did_decoder_functions[];
extern const OSSL_DISPATCH ossl_PrivateKeyInfo_der_to_vc_decoder_functions[];
extern const OSSL_DISPATCH ossl_SubjectPublicKeyInfo_der_to_vc_decoder_functions[];

/* OP_SIGNA[TURE */
extern const OSSL_DISPATCH ossl_vc_signature_functions[];