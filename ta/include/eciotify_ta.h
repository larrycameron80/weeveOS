/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TA_ECIOTIFY_H
#define TA_ECIOTIFY_H

#include <ta_common.h>

/**
 *	Functions
 */ 
TEE_Result del_keys(void);
TEE_Result gen_keys(void);
TEE_Result gen_bc_key(void);
TEE_Result register_device(uint32_t param_types, TEE_Param params[4]);
TEE_Result save_bc_keys(uint32_t param_types, TEE_Param params[4]);
TEE_Result check_memory_region(uint32_t param_types, TEE_Param params[4]);
TEE_Result blockchain_wallet(uint32_t param_types, TEE_Param params[4]);
TEE_Result get_hash(void *storage_id, uint32_t storage_id_len, uint8_t* out, uint32_t outsz);
TEE_Result store_hash(void *storage_id, uint32_t storage_id_len, void* hash, uint32_t hash_len);
TEE_Result ecc_operation(TEE_ObjectHandle key, TEE_OperationMode mode, uint32_t alg, TEE_Attribute *params, uint32_t paramCount, void *in_chunk, uint32_t in_chunk_len, void *out_chunk, uint32_t *out_chunk_len);
TEE_Result get_key_object(void *storage_id, uint32_t storage_id_len, TEE_ObjectHandle *keys);
TEE_Result hash(uint32_t algo, uint32_t mode, void *in, uint32_t insz, void *out, uint32_t *outsz);
TEE_Result aes_gcm_cipher(TEE_ObjectHandle key_handler, void *in, uint32_t insz,	void *out, uint32_t *outsz, void *tag, uint32_t *tagsz, uint8_t* iv, uint32_t ivsz, uint32_t alg, uint32_t mode);
TEE_Result return_ecdsa_keys(uint32_t param_types, TEE_Param params[4]);
TEE_Result return_ecdh_keys(uint32_t param_types, TEE_Param params[4]);
TEE_Result return_sign_keys(uint32_t param_types, TEE_Param params[4]);
TEE_Result verify_signature(uint32_t param_types, TEE_Param params[4]);
TEE_Result get_device_id(uint32_t param_types, TEE_Param params[4]);
TEE_Result create_credential_keys(uint32_t param_types);
TEE_Result delete_persistent_object(uint32_t param_types, TEE_Param params[4]);
TEE_Result delete_persistent_files(void *derived_storage_id, int derived_storage_id_len);
TEE_Result aes128_gcm_decrypt(uint32_t param_types, TEE_Param params[4]);
TEE_Result aes128_gcm_encrypt(uint32_t param_types, TEE_Param params[4]);
TEE_Result derive_from_public_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result verify_broker_signature(uint32_t param_types, TEE_Param params[4]);
TEE_Result get_broker_dsa_key(uint32_t param_types, TEE_Param params[4]);
TEE_Result save_signature(uint32_t param_types, TEE_Param params[4]);
TEE_Result get_signature(uint32_t param_types, TEE_Param params[4]);
void* kdf(void *msk, int msk_len, uint32_t *output_keys_len);
void printCharValue(uint8_t* value, int size);
void printHexValue(uint8_t* value, int size);


#endif /*TA_ECIOTIFY_H*/
