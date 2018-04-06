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

#define STR_TRACE_USER_TA "ECIOTIFY"

#include <ta_common.h>
#include <eciotify_generals.h>
#include <eciotify_ta.h>

#include <string.h>

#include <inttypes.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static TEE_OperationHandle digest_op = NULL;

const TEE_UUID ETH_INTERFACE_UUID = { 0x1072c20c, 0xd9aa, 0x11e7, \
{ 0x92, 0x96, 0xce, 0xc2, 0x78, 0xb6, 0xb5, 0x0a} };

char testimony_storage_id[] = {'D', 'S', 'A', 'K', 'E', 'Y', 'T', 'M'};
char wallet_storage_id[] = {'D', 'S', 'A', 'K', 'E', 'Y', 'B', 'C'};
char mqtts_dh_storage_id[] = {'D', 'H', 'K', 'E', 'Y', 'M', 'Q'};
char mqtts_dsa_storage_id[] = {'D', 'S', 'A', 'K', 'E', 'Y', 'M', 'Q'};
char device_id_descriptor[] = {'D', 'E', 'V', 'I', 'C', 'E', 'I', 'D'};
char eth_pub_key_id[] = {'D', 'S', 'A', 'P', 'U', 'B', 'B', 'C'};
char eth_priv_key_id[] = {'D', 'S', 'A', 'P', 'R', 'V', 'B', 'C'};
char eth_addr_key_id[] = {'E', 'T', 'H', 'A', 'D', 'D', 'R', 'E', 'S', 'S'};

char broker_signature_id[] = {'B', 'R', 'O', 'K', 'E', 'R', 'S', 'I', 'G'};

char signature_storage_id[] = {'S', 'I', 'G', 'N', 'A', 'T', 'U', 'R', 'E'};
char reg1_storage_id[] = {'H', '0'};
char reg2_storage_id[] = {'H', '1'};
char reg3_storage_id[] = {'H', '2'};
char reg4_storage_id[] = {'H', '3'};
char hfinal_storage_id[] = {'H', 'F', 'I', 'N', 'A', 'L'};

TEE_Result del_keys(void)
{
	TEE_Result res;
	
	res = delete_persistent_files(testimony_storage_id, sizeof(testimony_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("testimony_storage_id failed");

	res = delete_persistent_files(wallet_storage_id, sizeof(wallet_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("wallet_storage_id failed");

	res = delete_persistent_files(mqtts_dh_storage_id, sizeof(mqtts_dh_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("mqtts_dh_storage_id failed");

	res = delete_persistent_files(mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("mqtts_dsa_storage_id failed");

	res = delete_persistent_files(device_id_descriptor, sizeof(device_id_descriptor));
	if(res != TEE_SUCCESS)
		DMSG("device_id_descriptor failed");

	res = delete_persistent_files(eth_pub_key_id, sizeof(eth_pub_key_id));
	if(res != TEE_SUCCESS)
		DMSG("eth_pub_key_id failed");

	res = delete_persistent_files(eth_priv_key_id, sizeof(eth_priv_key_id));	
	if(res != TEE_SUCCESS)
		DMSG("eth_priv_key_id failed");

	res = delete_persistent_files(eth_addr_key_id, sizeof(eth_addr_key_id));
	if(res != TEE_SUCCESS)
		DMSG("eth_addr_key_id failed");

	res = delete_persistent_files(signature_storage_id, sizeof(signature_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("signature_storage_id failed");

	res = delete_persistent_files(reg1_storage_id, sizeof(reg1_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("reg1_storage_id failed");

	res = delete_persistent_files(reg2_storage_id, sizeof(reg2_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("reg2_storage_id failed");

	res = delete_persistent_files(reg3_storage_id, sizeof(reg3_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("reg3_storage_id failed");

	res = delete_persistent_files(reg4_storage_id, sizeof(reg4_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("reg4_storage_id failed");

	res = delete_persistent_files(hfinal_storage_id, sizeof(hfinal_storage_id));
	if(res != TEE_SUCCESS)
		DMSG("hfinal_storage_id failed");
	return res;
}

TEE_Result gen_keys(void)
{
	TEE_Result res;
	TEE_ObjectHandle *persistent_sigkey_obj = TEE_HANDLE_NULL;
	TEE_ObjectHandle sig_key;
	TEE_ObjectHandle persistent_signature_obj;
	TEE_ObjectHandle persistent_h0_obj;
	TEE_ObjectHandle persistent_h1_obj;
	TEE_ObjectHandle persistent_h2_obj;
	TEE_ObjectHandle persistent_h3_obj;
	TEE_ObjectHandle persistent_hfinal_obj;

	TEE_Attribute attr[1];
	uint32_t attr_size = 1;
	int ecdsa_key_size = 256;
	
	uint8_t iv[20] = { 0 };
	uint8_t signature[64] = { 0 };

	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, ecdsa_key_size, &sig_key);
	if(res != TEE_SUCCESS)
		return res;

	// Generate signature keys
	res = TEE_GenerateKey(sig_key, ecdsa_key_size, attr, attr_size);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, testimony_storage_id, sizeof(testimony_storage_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, sig_key, iv, 0, persistent_sigkey_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, signature_storage_id, sizeof(signature_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, signature, sizeof(signature), &persistent_signature_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, reg1_storage_id, sizeof(reg1_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, sizeof(iv), &persistent_h0_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, reg2_storage_id, sizeof(reg2_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, sizeof(iv), &persistent_h1_obj);	
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, reg3_storage_id, sizeof(reg3_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, sizeof(iv), &persistent_h2_obj);	
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, reg4_storage_id, sizeof(reg4_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, sizeof(iv), &persistent_h3_obj);	
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, hfinal_storage_id, sizeof(hfinal_storage_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, iv, sizeof(iv), &persistent_hfinal_obj);	
	if(res != TEE_SUCCESS)
		return res;

	TEE_FreeTransientObject(sig_key);
	TEE_CloseObject(persistent_h0_obj);
	TEE_CloseObject(persistent_h1_obj); 
	TEE_CloseObject(persistent_h2_obj);
	TEE_CloseObject(persistent_h3_obj);
	TEE_CloseObject(persistent_hfinal_obj);
	TEE_CloseObject(persistent_signature_obj);

	return res;
}

TEE_Result gen_bc_key(void)
{
	TEE_Result res;
	TEE_ObjectHandle persistent_sigkey_obj;
	TEE_ObjectHandle sig_key;

	TEE_Attribute attr[1];
	uint32_t attr_size = 1;
	int maxKeySize = 256;
	
	

	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, maxKeySize, &sig_key);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_GenerateKey(sig_key, maxKeySize, attr, attr_size);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, wallet_storage_id, sizeof(wallet_storage_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, sig_key, NULL, 0, &persistent_sigkey_obj);
	if(res != TEE_SUCCESS)
		return res;

	TEE_CloseObject(persistent_sigkey_obj);
	TEE_FreeTransientObject(sig_key);

	return res;
}

TEE_Result register_device(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle vk_mqtts;
	TEE_ObjectHandle vk_testimony;
	TEE_ObjectHandle vk_blockchain;
	TEE_ObjectHandle persistent_device_id_obj;

	uint8_t device_id[128];
	uint8_t vk_mqtts_public[64];
	uint8_t vk_testimony_public[64];
	uint8_t vk_blockchain_public[64];

	char *vk_mqtts_public_hex = NULL;
	char *vk_testimony_public_hex = NULL;
	char *vk_blockchain_public_hex = NULL;

	void *vk_mqtts_public_x = NULL;
	void *vk_mqtts_public_y = NULL;

	void *vk_testimony_public_x = NULL;
	void *vk_testimony_public_y = NULL;

	void *vk_blockchain_public_x = NULL;
	void *vk_blockchain_public_y = NULL;

	uint32_t exp_param_types, device_id_len;
	uint32_t public_key_len = 32;
	
	vk_mqtts_public_x = TEE_Malloc(public_key_len, 0);
	vk_mqtts_public_y = TEE_Malloc(public_key_len, 0);

	vk_testimony_public_x = TEE_Malloc(public_key_len, 0);
	vk_testimony_public_y = TEE_Malloc(public_key_len, 0);

	vk_blockchain_public_x = TEE_Malloc(public_key_len, 0);
	vk_blockchain_public_y = TEE_Malloc(public_key_len, 0);

	vk_mqtts_public_hex = TEE_Malloc(public_key_len*4, 0);
	vk_testimony_public_hex = TEE_Malloc(public_key_len*4, 0);
	vk_blockchain_public_hex = TEE_Malloc(public_key_len*4, 0);

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	device_id_len = params[0].memref.size;
	TEE_MemMove(device_id, params[0].memref.buffer, device_id_len);
 	
 	//store device id
 	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, device_id_descriptor, sizeof(device_id_descriptor), TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, device_id, device_id_len, &persistent_device_id_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = get_key_object(mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id), &vk_mqtts);
	if (res != TEE_SUCCESS)
		return res;
	res = get_key_object(testimony_storage_id, sizeof(testimony_storage_id), &vk_testimony);
	if (res != TEE_SUCCESS)
		return res;
	res = get_key_object(wallet_storage_id, sizeof(wallet_storage_id), &vk_blockchain);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(vk_mqtts, TEE_ATTR_ECC_PUBLIC_VALUE_X, vk_mqtts_public_x, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectBufferAttribute(vk_mqtts, TEE_ATTR_ECC_PUBLIC_VALUE_Y, vk_mqtts_public_y, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	TEE_MemMove(vk_mqtts_public, vk_mqtts_public_x, public_key_len);
	TEE_MemMove(vk_mqtts_public+public_key_len, vk_mqtts_public_y, public_key_len);


	res = TEE_GetObjectBufferAttribute(vk_testimony, TEE_ATTR_ECC_PUBLIC_VALUE_X, vk_testimony_public_x, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectBufferAttribute(vk_testimony, TEE_ATTR_ECC_PUBLIC_VALUE_Y, vk_testimony_public_y, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	TEE_MemMove(vk_testimony_public, vk_testimony_public_x, public_key_len);
	TEE_MemMove(vk_testimony_public+public_key_len, vk_testimony_public_y, public_key_len);


	res = TEE_GetObjectBufferAttribute(vk_blockchain, TEE_ATTR_ECC_PUBLIC_VALUE_X, vk_blockchain_public_x, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectBufferAttribute(vk_blockchain, TEE_ATTR_ECC_PUBLIC_VALUE_Y, vk_blockchain_public_y, &public_key_len);
	if(res != TEE_SUCCESS)
		return res;
	TEE_MemMove(vk_blockchain_public, vk_blockchain_public_x, public_key_len);
	TEE_MemMove(vk_blockchain_public+public_key_len, vk_blockchain_public_y, public_key_len);


	for (uint32_t i = 0; i < sizeof(vk_mqtts_public); i++)
	{
		snprintf(vk_mqtts_public_hex+i*2, 128, "%02x", vk_mqtts_public[i]);
	}
	for (uint32_t i = 0; i < sizeof(vk_testimony_public); i++)
	{
		snprintf(vk_testimony_public_hex+i*2, 128, "%02x", vk_testimony_public[i]);
	}
	for (uint32_t i = 0; i < sizeof(vk_blockchain_public); i++)
	{
		snprintf(vk_blockchain_public_hex+i*2, 128, "%02x", vk_blockchain_public[i]);
	}

	TEE_MemFill(vk_mqtts_public_hex+strlen(vk_mqtts_public_hex), '\0', 1);
	TEE_MemFill(vk_testimony_public_hex+strlen(vk_testimony_public_hex), '\0', 1);
	TEE_MemFill(vk_blockchain_public_hex+strlen(vk_blockchain_public_hex), '\0', 1);

	TEE_MemMove(params[1].memref.buffer, vk_mqtts_public_hex, strlen(vk_mqtts_public_hex));
 	params[1].memref.size = strlen(vk_mqtts_public_hex);

 	TEE_MemMove(params[2].memref.buffer, vk_testimony_public_hex, strlen(vk_testimony_public_hex));
 	params[2].memref.size = strlen(vk_testimony_public_hex);

 	TEE_MemMove(params[3].memref.buffer, vk_blockchain_public_hex, strlen(vk_blockchain_public_hex));
 	params[3].memref.size = strlen(vk_blockchain_public_hex);

 	TEE_CloseObject(persistent_device_id_obj);
	return res;
}

TEE_Result save_bc_keys(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle persistent_eth_pub_obj;
	TEE_ObjectHandle persistent_eth_prv_obj;
	TEE_ObjectHandle persistent_eth_add_obj;

	uint32_t exp_param_types;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

 	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, eth_pub_key_id, sizeof(eth_pub_key_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, params[0].memref.buffer, params[0].memref.size, &persistent_eth_pub_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, eth_priv_key_id, sizeof(eth_priv_key_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, params[1].memref.buffer, params[1].memref.size, &persistent_eth_prv_obj);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, eth_addr_key_id, sizeof(eth_addr_key_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, params[2].memref.buffer, params[2].memref.size, &persistent_eth_add_obj);
	if(res != TEE_SUCCESS)
		return res;

	return res;
}

TEE_Result check_memory_region(uint32_t param_types, TEE_Param params[4])
{	
	//TA
	// TEE_TASessionHandle sess;
	// TEE_Param params_static;

	TEE_Result res;
	TEE_ObjectHandle key_handler;
	TEE_Attribute attr[1];

	void *out, *in;
	void *signature = NULL;
	
	int sha1_size = 20;
	int mode;
	uint8_t h1[20] = { 0 };
	uint8_t iv[20] = { 0 };
	uint8_t reg3[20] = { 0 };
	uint8_t hfinal[20] = { 0 };
	uint8_t* concat_h = NULL;

	uint32_t attr_size = 1;
	uint32_t signature_len = 64;
	uint32_t insz, outsz, exp_param_types, h_size;// ret_origin;

	DMSG("Creating testimony...");

	//TEST
	// res = TEE_OpenTASession(&ETH_INTERFACE_UUID, 0, 0, NULL, &sess, &ret_origin);
	// if (res != TEE_SUCCESS)
	// 	return res;

	// res = TEE_InvokeTACommand(sess, 0, 0, 0, &params_static, &ret_origin);
	// if (res != TEE_SUCCESS)
	// 	return res;

	// TEE_CloseTASession(sess);
	//END TEST


	signature = TEE_Malloc(signature_len, 0);
	outsz = 0;

	//attributes for the signature algorythm
	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_VALUE_INOUT, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	in = (long long int *)params[0].memref.buffer;
	insz = params[1].value.a*sizeof(long long int);
	out = (long long int *)params[0].memref.buffer;
	outsz = sha1_size;
	mode = params[2].value.a;

	res = hash(TEE_ALG_SHA1, TEE_MODE_DIGEST, in, insz, out, &outsz);
	if (res != TEE_SUCCESS)
		return res;

	if (mode == 0) 
	{
		h_size = outsz;

		res = store_hash(reg1_storage_id, sizeof(reg1_storage_id), out, h_size);
		if(res != TEE_SUCCESS)
			return res;
	}
	else if (mode == 1) 
	{
		h_size = outsz;

		res = store_hash(reg2_storage_id, sizeof(reg2_storage_id), out, h_size);
		if(res != TEE_SUCCESS)
			return res;

		res = get_hash(reg1_storage_id, sizeof(reg1_storage_id), h1, h_size);
		if(res != TEE_SUCCESS)
			return res;

		res = get_hash(reg3_storage_id, sizeof(reg3_storage_id), reg3, h_size);
		if(res != TEE_SUCCESS)
			return res;

		//STRING GENERATE
		concat_h = TEE_Malloc(h_size*3, TEE_MALLOC_FILL_ZERO);

		TEE_MemMove(concat_h, h1, h_size);
		TEE_MemMove(concat_h+h_size, out, h_size);
		TEE_MemMove(concat_h+h_size*2, reg3, h_size);

		in = concat_h;
		insz = h_size*3;
		out = concat_h;
		outsz = sha1_size;

		res = hash(TEE_ALG_SHA1, TEE_MODE_DIGEST, in, insz, out, &outsz);
		if (res != TEE_SUCCESS)
			return res;

		res = store_hash(reg3_storage_id, sizeof(reg3_storage_id), out, outsz);
		if(res != TEE_SUCCESS)
			return res;

		TEE_Free(concat_h);
	}
	else if (mode == 2) 
	{
		h_size = outsz;

		res = store_hash(reg4_storage_id, sizeof(reg4_storage_id), out, h_size);
		if(res != TEE_SUCCESS)
			return res;

		res = get_hash(reg3_storage_id, sizeof(reg3_storage_id), reg3, h_size);
		if(res != TEE_SUCCESS)
			return res;

		//STRING GENERATE
		concat_h = TEE_Malloc(h_size*2, TEE_MALLOC_FILL_ZERO);

		TEE_MemMove(concat_h, reg3, h_size);
		TEE_MemMove(concat_h+h_size, out, h_size);

		in = concat_h;
		insz = h_size*2;
		out = concat_h;
		outsz = sha1_size;

		res = hash(TEE_ALG_SHA1, TEE_MODE_DIGEST, in, insz, out, &outsz);
		if (res != TEE_SUCCESS)
			return res;

		res = store_hash(hfinal_storage_id, sizeof(hfinal_storage_id), out, outsz);
		if(res != TEE_SUCCESS)
			return res;

		res = get_hash(hfinal_storage_id, sizeof(hfinal_storage_id), hfinal, h_size);
		if(res != TEE_SUCCESS)
			return res;

		//SET IV, CAUSE STORAGES STILL FILLED
		res = store_hash(reg3_storage_id, sizeof(reg3_storage_id), iv, sha1_size);
		if(res != TEE_SUCCESS)
			return res;

		//sign
		res = get_key_object(testimony_storage_id, sizeof(testimony_storage_id), &key_handler);
		if(res != TEE_SUCCESS)
			return res;

		res = ecc_operation(key_handler, TEE_MODE_SIGN, TEE_ALG_ECDSA_P256, attr, attr_size, hfinal, h_size, signature, &signature_len);
		if(res != TEE_SUCCESS)
			return res;

		res = store_hash(signature_storage_id, sizeof(signature_storage_id), signature, signature_len);
		if(res != TEE_SUCCESS)
			return res;

		TEE_Free(concat_h);
	}

	DMSG("Hashing done and saved to secure storage.");
	return TEE_SUCCESS;
}

TEE_Result blockchain_wallet(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_Time timestamp;
	TEE_ObjectHandle dsa_key_bc;
	TEE_Attribute attr[1];

	uint8_t signature_smart_contract[64];
	uint8_t hfinal[20];
	uint8_t signature[64];
	uint8_t *out_hash;
	uint8_t program_id;

	char* data;
	char* topic;

	uint32_t signature_len = 64;
	uint32_t hash_len = 64;

	uint32_t attr_size = 1;
	uint32_t amount, price, exp_param_types;
	uint8_t id[10];
	uint8_t *address;
	
	char json_template[1500];
	
	char *id_hex, *json_hex, *hfinal_hex, *signature_hex, *id_string, *signature_smart_contract_hex;

	DMSG("Creating testified smart contract...");

	//attributes for the signature algorythm
	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	//allocate some space for the variables
	
	topic = TEE_Malloc(params[2].memref.size+1, 0);
	id_hex = TEE_Malloc(sizeof(id)*2, 0);
	json_hex = TEE_Malloc(sizeof(json_template)*2+128, 0);
	hfinal_hex = TEE_Malloc(sizeof(hfinal)*2, 0);
	signature_hex = TEE_Malloc(sizeof(signature)*2, 0);
	signature_smart_contract_hex = TEE_Malloc(sizeof(signature_smart_contract)*2+1, 0);
	address = TEE_Malloc(42, 0);
	out_hash = TEE_Malloc(hash_len, 0);
	id_string = TEE_Malloc(3, 0);

	if (!topic || !id_hex || !json_hex || !hfinal_hex || !signature_hex || !signature_smart_contract_hex || !address || !out_hash || !id_string) {
		return TEE_ERROR_STORAGE_NO_SPACE;
	}
	
	//get current timestap in seconds since 01.01.1970
	TEE_GetREETime(&timestamp);

	//generate random bytes and save as id
	TEE_GenerateRandom(id, sizeof(id));	

	TEE_MemMove(topic, params[2].memref.buffer, params[2].memref.size);
	TEE_MemFill(topic+params[2].memref.size, '\0', 1);

	if (params[1].memref.size > 0) 
	{
		data = TEE_Malloc(params[1].memref.size+1, 0);
		TEE_MemMove(data, params[1].memref.buffer, params[1].memref.size);
		TEE_MemFill(data+params[1].memref.size, '\0', 1);

		program_id = 0;
		TEE_MemMove(id_string, "sid", 3);
	}
	else if (params[1].memref.size == 0)
	{
		data = TEE_Malloc(5, 0);
		TEE_MemMove(data, "none", 4);
		TEE_MemFill(data+4, '\0', 1);

		program_id = 1;
		TEE_MemMove(id_string, "did", 3);
	}

	TEE_MemFill(id_string+3, '\0', 1);

	//populate the inputs
	amount = params[0].value.a;
	price = params[0].value.b;

	//get the address out of the secure storage
	res = get_hash(eth_addr_key_id, sizeof(eth_addr_key_id), address, 42);
	if(res != TEE_SUCCESS)
		return res;

	TEE_MemFill(address+42, '\0', 1);

	//get the hfinal out of the secure storage
	res = get_hash(hfinal_storage_id, sizeof(hfinal_storage_id), hfinal, sizeof(hfinal));
	if(res != TEE_SUCCESS)
		return res;

	//get the testimony signature out of the secure storage
	res = get_hash(signature_storage_id, sizeof(signature_storage_id), signature, sizeof(signature));
	if(res != TEE_SUCCESS)
		return res;

	//Convert id to hex and save as string
	for (uint32_t i = 0; i < sizeof(id); i++)
	{
		snprintf(id_hex+i*2, sizeof(id)*2, "%02x", id[i]);
	}

	//Convert hfinal to hex and save as string
	for (uint32_t i = 0; i < sizeof(hfinal); i++)
	{
		snprintf(hfinal_hex+i*2, sizeof(hfinal)*2, "%02x", hfinal[i]);
	}

	//Convert signature to hex and save as string
	for (uint32_t i = 0; i < sizeof(signature); i++)
	{
		snprintf(signature_hex+i*2, sizeof(signature)*2, "%02x", signature[i]);
	}

	snprintf(json_template, sizeof(json_template), "{\"topic\": \"%s\", \"%s\": \"%s\", \"bc_address\": \"%s\", \"date\": %i, \"currency\": \"ETH\", \"price\": %i, \"amount\": %i, \"data\": \"%s\", \"additional_conditions\": \"none\", \"program_id\": %i, \"testimony\": \"%s\", \"testimony_signature\": \"%s\"}", topic, id_string, id_hex, address, timestamp.seconds, price, amount, data, program_id, hfinal_hex, signature_hex);

	for (uint32_t i = 0; i < strlen(json_template); i++)
	{
		snprintf(json_hex+i*2, sizeof(json_template)*2, "%02x", json_template[i]);
	}

	res = get_key_object(wallet_storage_id, sizeof(wallet_storage_id), &dsa_key_bc);
	if(res != TEE_SUCCESS)
		return res;

	res = hash(TEE_ALG_SHA256, TEE_MODE_DIGEST, json_hex, strlen(json_hex), out_hash, &hash_len);
		if (res != TEE_SUCCESS)
			return res;

	res = ecc_operation(dsa_key_bc, TEE_MODE_SIGN, TEE_ALG_ECDSA_P256, attr, attr_size, out_hash, hash_len, signature_smart_contract, &signature_len);
	if(res != TEE_SUCCESS)
		return res;
	
	for (uint32_t i = 0; i < sizeof(signature_smart_contract); i++)
	{
		snprintf(signature_smart_contract_hex+i*2, sizeof(signature)*2, "%02x", signature_smart_contract[i]);
	}

	// TEE_MemMove(json_hex+strlen(json_hex), signature_smart_contract_hex, strlen(signature_smart_contract_hex));
	TEE_MemFill(signature_smart_contract_hex+strlen(signature_smart_contract_hex), '\0', 1);
	TEE_MemFill(json_hex+strlen(json_hex), '\0', 1);

	TEE_MemMove(params[3].memref.buffer, json_hex, strlen(json_hex));
 	TEE_MemMove((char *)params[3].memref.buffer+strlen(json_hex), signature_smart_contract_hex, strlen(signature_smart_contract_hex));
 	params[3].memref.size = strlen(signature_smart_contract_hex) + strlen(json_hex);

 	DMSG("tSC created and sent to normal world.");
	return res;
}

TEE_Result get_hash(void *storage_id, uint32_t storage_id_len, uint8_t* out, uint32_t outsz)
{
	TEE_Result res;
	TEE_ObjectHandle hashobject;
	uint32_t count = 0;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storage_id, storage_id_len, TEE_DATA_FLAG_ACCESS_READ, &hashobject);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_ReadObjectData(hashobject, out, outsz, &count);
	if(res != TEE_SUCCESS )
		return res;

	TEE_CloseObject(hashobject); 

	return res;	
}

TEE_Result store_hash(void *storage_id, uint32_t storage_id_len, void* hash, uint32_t hash_len)
{
	TEE_Result res;
	TEE_ObjectHandle hashobject = TEE_HANDLE_NULL;

	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storage_id, storage_id_len, TEE_DATA_FLAG_ACCESS_WRITE, &hashobject);
	if(res != TEE_SUCCESS )
		return res;

	res = TEE_WriteObjectData(hashobject, hash, hash_len);
	if(res != TEE_SUCCESS )
		return res;

	TEE_CloseObject(hashobject); 

	return res;
}

TEE_Result ecc_operation(TEE_ObjectHandle key, TEE_OperationMode mode, uint32_t alg, TEE_Attribute *params, uint32_t paramCount, void *in_chunk, uint32_t in_chunk_len, void *out_chunk, uint32_t *out_chunk_len)
{
	TEE_Result res = TEE_SUCCESS;
	TEE_OperationHandle handle = (TEE_OperationHandle) NULL;
	TEE_ObjectInfo info;

	TEE_GetObjectInfo1(key, &info);

	res = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_SetOperationKey(handle, key);
	if (res != TEE_SUCCESS)
		return res;

	if (mode == TEE_MODE_SIGN) {
		res = TEE_AsymmetricSignDigest(
			handle, 
			params, 
			paramCount,
			in_chunk, 
			in_chunk_len, 
			out_chunk, 
			out_chunk_len
		);
	} 
	else if (mode == TEE_MODE_VERIFY) 
	{
		res = TEE_AsymmetricVerifyDigest(
			handle, 
			params, 
			paramCount,
			in_chunk, 
			in_chunk_len, 
			out_chunk, 
			*out_chunk_len
		);
	}
	else 
	{
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_FreeOperation(handle);
	return res;
}

TEE_Result get_key_object(void *storage_id, uint32_t storage_id_len, TEE_ObjectHandle *keys)
{
	uint32_t output_size = 0;
	TEE_Result res;
	
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, storage_id, storage_id_len, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, keys );
	if(res != TEE_SUCCESS )
		return res;
	
	
	res = TEE_ReadObjectData(*keys, NULL,0, &output_size);

	return res;
}

TEE_Result hash(uint32_t algo, uint32_t mode, void *chunk, uint32_t insz, void *out, uint32_t *outsz) 
{
	TEE_Result res;

	if (digest_op)
		TEE_FreeOperation(digest_op);

	res = TEE_AllocateOperation(&digest_op, algo, mode, 0);
	if(res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	res = TEE_DigestDoFinal(digest_op, chunk, insz, out, outsz);
	if(res != TEE_SUCCESS)
		return TEE_ERROR_BAD_PARAMETERS;

	return res;
}

TEE_Result aes_gcm_cipher(TEE_ObjectHandle key_handler, void *in, uint32_t insz,	void *out, uint32_t *outsz, void *tag, uint32_t *tagsz, uint8_t* iv, uint32_t ivsz, uint32_t alg, uint32_t mode)
{
	TEE_Attribute attr[1];
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle aes_key = TEE_HANDLE_NULL;
	TEE_OperationHandle handle = TEE_HANDLE_NULL;
	TEE_ObjectInfo info;
	void *secret = NULL;
	uint32_t secret_len = 32;
	int tag_size_bit = 128;

	
	TEE_GetObjectInfo1(key_handler, &info);
	secret = TEE_Malloc(secret_len, 0);
	
	res = TEE_AllocateOperation(&handle, alg, mode, info.maxObjectSize);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(key_handler, TEE_ATTR_SECRET_VALUE, secret, &secret_len);
	if (res != TEE_SUCCESS)
		return res;

	attr[0].attributeID = TEE_ATTR_SECRET_VALUE;
	attr[0].content.ref.buffer = secret;
	attr[0].content.ref.length = secret_len;

	res = TEE_AllocateTransientObject(
		TEE_TYPE_AES,
		256, 
		&aes_key
	);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_PopulateTransientObject(aes_key, attr, 1 );
	if (res != TEE_SUCCESS)
		return res;


	res = TEE_SetOperationKey(handle, aes_key);
	if (res != TEE_SUCCESS)
		return res;

	if (mode == TEE_MODE_ENCRYPT) 
	{	
		res = TEE_AEInit(handle, iv, ivsz, tag_size_bit, 0, 0);
		if (res != TEE_SUCCESS)
			return res;
		
		res = TEE_AEEncryptFinal(handle, in, insz, out, outsz, tag, tagsz );
		if (res != TEE_SUCCESS)
			return res;

	} 
	else if (mode == TEE_MODE_DECRYPT) 
	{
		res = TEE_AEInit(handle, iv, ivsz, tag_size_bit, 0, 0);
		if (res != TEE_SUCCESS)
			return res;

		res = TEE_AEDecryptFinal(handle, in, insz, out, outsz, tag, *tagsz );
		
		if (res != TEE_SUCCESS)
			return res;
	}
	else 
	{
		res = TEE_ERROR_BAD_PARAMETERS;
	}

	TEE_Free(secret);
	TEE_FreeOperation(handle);
	return res;
}

TEE_Result return_ecdsa_keys(uint32_t param_types, TEE_Param params[4]) 
{
	TEE_Result res;
	TEE_ObjectHandle ecdsa_keys;

	uint32_t ecdsa_public_key_len = 32;
	void *ecdsa_public_x = NULL;
	void *ecdsa_public_y = NULL;
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ecdsa_public_x = TEE_Malloc(ecdsa_public_key_len, 0);
	ecdsa_public_y = TEE_Malloc(ecdsa_public_key_len, 0);

	if (!ecdsa_public_x || !ecdsa_public_y) 
		return TEE_ERROR_OUT_OF_MEMORY;

	res = get_key_object(mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id), &ecdsa_keys);
	if(res != TEE_SUCCESS )
		return res;	

	res = TEE_GetObjectBufferAttribute(ecdsa_keys, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecdsa_public_x, &ecdsa_public_key_len);
	res = TEE_GetObjectBufferAttribute(ecdsa_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecdsa_public_y, &ecdsa_public_key_len);

	TEE_MemMove(params[0].memref.buffer, ecdsa_public_x, ecdsa_public_key_len);
	params[0].memref.size = ecdsa_public_key_len;
	
	TEE_MemMove(params[1].memref.buffer, ecdsa_public_y, ecdsa_public_key_len);
	params[1].memref.size = ecdsa_public_key_len;
	
	TEE_Free(ecdsa_public_x);
	TEE_Free(ecdsa_public_y);
	return res; 
}

TEE_Result return_ecdh_keys(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle ecdh_keys;

	uint32_t ecdh_public_key_len = 32;
	void *ecdh_public_x = NULL;
	void *ecdh_public_y = NULL;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ecdh_public_x = TEE_Malloc(ecdh_public_key_len, 0);
	ecdh_public_y = TEE_Malloc(ecdh_public_key_len, 0);
	
	if (!ecdh_public_x || !ecdh_public_y)
		return TEE_ERROR_OUT_OF_MEMORY;

	res = get_key_object(mqtts_dh_storage_id, sizeof(mqtts_dh_storage_id), &ecdh_keys);
	if(res != TEE_SUCCESS )
		return res;

	res = TEE_GetObjectBufferAttribute(ecdh_keys, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecdh_public_x, &ecdh_public_key_len);
	res = TEE_GetObjectBufferAttribute(ecdh_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecdh_public_y, &ecdh_public_key_len);


	TEE_MemMove(params[0].memref.buffer, ecdh_public_x, ecdh_public_key_len);
	params[0].memref.size = ecdh_public_key_len;
	
	TEE_MemMove(params[1].memref.buffer, ecdh_public_y, ecdh_public_key_len);
	params[1].memref.size = ecdh_public_key_len;

	return res; 
}

TEE_Result return_sign_keys(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle ecdsa_keys;
	TEE_ObjectHandle ecdh_keys;
	TEE_Attribute attr[1];
	uint32_t attr_size = 1;

	uint32_t ecdsa_public_key_len = 32;
	void *ecdsa_public_x = NULL;
	void *ecdsa_public_y = NULL;
	
	uint32_t ecdh_public_key_len = 32;
	void *ecdh_public_x = NULL;
	void *ecdh_public_y = NULL;

	void *signature = NULL;
	uint32_t signature_len = 64;

	uint8_t *out_hash;
	uint32_t hash_len = 64;
	
	uint8_t public_keys[(ecdsa_public_key_len*2) + (ecdh_public_key_len*2)];
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ecdsa_public_x = TEE_Malloc(ecdsa_public_key_len, 0);
	ecdsa_public_y = TEE_Malloc(ecdsa_public_key_len, 0);

	ecdh_public_x = TEE_Malloc(ecdh_public_key_len, 0);
	ecdh_public_y = TEE_Malloc(ecdh_public_key_len, 0);

	signature = TEE_Malloc(signature_len, 0);
	out_hash = TEE_Malloc(hash_len, 0);
	
	if (!signature || !ecdsa_public_x || !ecdsa_public_y || !ecdh_public_x || !ecdh_public_y) 
		return TEE_ERROR_OUT_OF_MEMORY;

	res = get_key_object(mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id), &ecdsa_keys);
	if(res != TEE_SUCCESS )
		return res;	

	res = TEE_GetObjectBufferAttribute(ecdsa_keys, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecdsa_public_x, &ecdsa_public_key_len);
	res = TEE_GetObjectBufferAttribute(ecdsa_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecdsa_public_y, &ecdsa_public_key_len);

	TEE_MemMove(public_keys, ecdsa_public_x, ecdsa_public_key_len);
	TEE_MemMove(&public_keys[ecdsa_public_key_len], ecdsa_public_y, ecdsa_public_key_len);
	
	res = get_key_object(mqtts_dh_storage_id, sizeof(mqtts_dh_storage_id), &ecdh_keys);
	if(res != TEE_SUCCESS )
		return res;

	res = TEE_GetObjectBufferAttribute(ecdh_keys, TEE_ATTR_ECC_PUBLIC_VALUE_X, ecdh_public_x, &ecdh_public_key_len);
	res = TEE_GetObjectBufferAttribute(ecdh_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, ecdh_public_y, &ecdh_public_key_len);

	TEE_MemMove(&public_keys[ecdsa_public_key_len*2], ecdh_public_x, ecdh_public_key_len);
	TEE_MemMove(&public_keys[(ecdsa_public_key_len*2)+ecdh_public_key_len], ecdh_public_y, ecdh_public_key_len);

	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	res = hash(TEE_ALG_SHA256, TEE_MODE_DIGEST, public_keys, sizeof(public_keys), out_hash, &hash_len);
		if (res != TEE_SUCCESS)
			return res;
	
	res = ecc_operation(
		ecdsa_keys, 
		TEE_MODE_SIGN, 
		TEE_ALG_ECDSA_P256, 
		attr, 
		attr_size, 
		out_hash, 
		hash_len, 
		signature, 
		&signature_len
	);
	if(res != TEE_SUCCESS)
		return res;

	TEE_MemMove(params[0].memref.buffer, signature, signature_len);
	params[0].memref.size = signature_len;
	
	TEE_Free(ecdsa_public_x);
	TEE_Free(ecdsa_public_y);
	TEE_Free(ecdh_public_x);
	TEE_Free(ecdh_public_y);
	return res; 
}

TEE_Result verify_signature(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle objectHandler;
	TEE_Attribute attr[1];
	TEE_Attribute key_attr[3];
	
	void *input_data = NULL;
	void *signature = NULL;
	void *input_key_x = NULL;
	void *input_key_y = NULL;
	uint8_t *ecdsa_keys;
	uint8_t *out_hash;

	int maxKeySize = 256;

	uint32_t input_data_len;
	uint32_t signature_len;
	uint32_t ecdsa_keys_len;
	uint32_t hash_len = 64;

	uint32_t attr_size = 1;
	uint32_t key_attr_size = 3;
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	input_data_len = params[0].memref.size;
	ecdsa_keys_len = params[1].memref.size;
	signature_len = params[2].memref.size;

	// Prepear for singing
	input_data = TEE_Malloc(input_data_len, 0);
	signature = TEE_Malloc(signature_len, 0);
	input_key_x = TEE_Malloc(ecdsa_keys_len/2, 0);
	input_key_y = TEE_Malloc(ecdsa_keys_len/2, 0);
	ecdsa_keys = TEE_Malloc(ecdsa_keys_len, 0);
	out_hash = TEE_Malloc(hash_len, 0);
	
	if (!input_data || !signature || !out_hash || !input_key_x || !input_key_y || !ecdsa_keys) 
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(input_data, params[0].memref.buffer, params[0].memref.size);
	TEE_MemMove(signature, params[2].memref.buffer, params[2].memref.size);

	ecdsa_keys = params[1].memref.buffer;

	TEE_MemMove(input_key_x, ecdsa_keys, ecdsa_keys_len/2);
	TEE_MemMove(input_key_y, &ecdsa_keys[ecdsa_keys_len/2], ecdsa_keys_len/2);

	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	key_attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	key_attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	key_attr[0].content.value.b = 0;

	key_attr[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	key_attr[1].content.ref.buffer = input_key_x;
	key_attr[1].content.ref.length = ecdsa_keys_len/2;
	
	key_attr[2].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	key_attr[2].content.ref.buffer = input_key_y;
	key_attr[2].content.ref.length = ecdsa_keys_len/2;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, maxKeySize, &objectHandler);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_PopulateTransientObject(objectHandler, key_attr, key_attr_size);
	if(res != TEE_SUCCESS)
		return res;

	res = hash(TEE_ALG_SHA256, TEE_MODE_DIGEST, input_data, input_data_len, out_hash, &hash_len);
	if (res != TEE_SUCCESS)
		return res;

	res = ecc_operation(
		objectHandler, 
		TEE_MODE_VERIFY, 
		TEE_ALG_ECDSA_P256, 
		attr,
		attr_size,
		out_hash, // Data to be verified
		hash_len,
		signature, // Signature for data 
		&signature_len
	);
	if(res != TEE_SUCCESS)
		return res;

	
	TEE_Free(ecdsa_keys);
	TEE_Free(input_key_y);
	TEE_Free(input_key_x);
	TEE_Free(signature);
	TEE_Free(input_data);
	return res;
}

TEE_Result get_device_id(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	uint8_t device_id[128] = {0};
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);
	
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hash(device_id_descriptor, sizeof(device_id_descriptor), device_id, sizeof(device_id));
		if(res != TEE_SUCCESS)
			return res;

	TEE_MemMove(params[0].memref.buffer, device_id, sizeof(device_id));

	return res;
}

TEE_Result create_credential_keys(uint32_t param_types)
{
	TEE_Result res;
	TEE_ObjectHandle ecdsa_keys;
	TEE_ObjectHandle ecdh_keys;
	TEE_Attribute attr[1];
	
	TEE_ObjectHandle persistent_ecdh_obj;
	TEE_ObjectHandle persistent_ecdsa_obj;

	int ecdsa_key_size = 256;
	int ecdh_key_size = 256;
	uint32_t attr_size = 1;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);
	DMSG("Create MQTTS KEYS");
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	attr[0].content.value.b = 0;

	res = TEE_AllocateTransientObject(
		TEE_TYPE_ECDSA_KEYPAIR,
		ecdsa_key_size, 
		&ecdsa_keys
	);
	if(res != TEE_SUCCESS)
		return res;

	// Generate signature keys
	res = TEE_GenerateKey(ecdsa_keys, ecdsa_key_size, attr, attr_size);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(
		TEE_TYPE_ECDH_KEYPAIR,
		ecdh_key_size, 
		&ecdh_keys
	);
	if(res != TEE_SUCCESS)
		return res;
	
	// Generate encryption keys
	res = TEE_GenerateKey(ecdh_keys, ecdh_key_size, attr, attr_size);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, mqtts_dh_storage_id, sizeof(mqtts_dh_storage_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, ecdh_keys, NULL, 0, &persistent_ecdh_obj);
	if(res != TEE_SUCCESS)
		return res;


	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id), TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, ecdsa_keys, NULL, 0, &persistent_ecdsa_obj);
	if(res != TEE_SUCCESS)
		return res;


	TEE_CloseObject(persistent_ecdh_obj);
	TEE_CloseObject(persistent_ecdsa_obj);
	TEE_FreeTransientObject(ecdh_keys);
	TEE_FreeTransientObject(ecdsa_keys);

	return res;
}

TEE_Result delete_persistent_object(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	int derived_storage_id_len;
	
	void *derived_storage_id = NULL;
	

	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE,
		TEE_PARAM_TYPE_NONE
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	derived_storage_id_len 	= params[0].memref.size;
	derived_storage_id 	= TEE_Malloc(derived_storage_id_len, 0);
	
	if(!derived_storage_id)
		return TEE_ERROR_OUT_OF_MEMORY;

	derived_storage_id  = params[0].memref.buffer;
	if (!derived_storage_id) 
		return TEE_ERROR_OUT_OF_MEMORY;


	res = delete_persistent_files(derived_storage_id, derived_storage_id_len);

	return res;
}

TEE_Result delete_persistent_files(void *derived_storage_id, int derived_storage_id_len)
{
	TEE_ObjectHandle keys;
	TEE_Result res;
	
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, derived_storage_id, derived_storage_id_len, TEE_DATA_FLAG_ACCESS_WRITE_META, &keys );
	if(res != TEE_SUCCESS )
		return res;
	
	res = TEE_CloseAndDeletePersistentObject1(keys);
	return res;
}

TEE_Result aes128_gcm_decrypt(uint32_t param_types, TEE_Param params[4])
{
	void *output = NULL; 
	uint8_t *cipher_and_iv = NULL; 
	void *tag = NULL;
	void *client_id = NULL;

	uint32_t output_len;
	uint32_t cipher_and_iv_len = 0;
	uint32_t tag_len;
	uint32_t client_id_len;
	
	uint8_t *cipher;

	uint8_t *iv;
	uint8_t iv_len = 16;	

	TEE_Result res;
	TEE_ObjectHandle secret_key_handler;


	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT
	);


	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	iv = TEE_Malloc(iv_len, 0);

	if (!iv) 
		return TEE_ERROR_OUT_OF_MEMORY;

	cipher_and_iv 		= params[0].memref.buffer;
	cipher_and_iv_len 	= params[0].memref.size;

	client_id 		= params[1].memref.buffer;
	client_id_len 	= params[1].memref.size; 
	
	tag 	= params[2].memref.buffer;
	tag_len = params[2].memref.size;

	output 		= params[3].memref.buffer;
	output_len 	= params[3].memref.size;

	cipher = TEE_Malloc(cipher_and_iv_len-iv_len, 0);
	if (!cipher) 
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_MemMove(cipher, cipher_and_iv, cipher_and_iv_len-iv_len);
	TEE_MemMove(iv, &cipher_and_iv[cipher_and_iv_len-iv_len], iv_len);
	

	res = get_key_object(client_id, client_id_len, &secret_key_handler);
	if(res != TEE_SUCCESS)
		return res;
	
	res = aes_gcm_cipher(
		secret_key_handler,
		cipher,
		cipher_and_iv_len-iv_len,
		output,
		&output_len,
		tag,
		&tag_len,
		iv,
		iv_len,
		TEE_ALG_AES_GCM,
		TEE_MODE_DECRYPT

	);
	
	if(res != TEE_SUCCESS)
		return res;

	TEE_Free(iv);
	TEE_Free(cipher);

	return res;
}

TEE_Result aes128_gcm_encrypt(uint32_t param_types, TEE_Param params[4])
{
	void *input = NULL; 
	uint8_t *cipher_and_iv = NULL; 
	void *tag = NULL;
	void *client_id = NULL;

	uint32_t input_len;
	uint32_t cipher_and_iv_len = 0;
	uint32_t tag_len;
	uint32_t client_id_len;
	
	uint8_t *iv;
	uint8_t iv_len = 16;	

	TEE_Result res;
	TEE_ObjectHandle secret_key_handler;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT,
		TEE_PARAM_TYPE_MEMREF_OUTPUT
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	input 		= params[0].memref.buffer;
	input_len 	= params[0].memref.size;

	client_id 		= params[1].memref.buffer;
	client_id_len 	= params[1].memref.size; 

	cipher_and_iv 		= params[2].memref.buffer;
	cipher_and_iv_len 	= params[2].memref.size;

	tag 	= params[3].memref.buffer;
	tag_len = params[3].memref.size;

	iv = TEE_Malloc(iv_len, 0);


	if (!iv) 
		return TEE_ERROR_OUT_OF_MEMORY;

	TEE_GenerateRandom(iv, iv_len);
	
	res = get_key_object(client_id, client_id_len, &secret_key_handler);
	if(res != TEE_SUCCESS)
		return res;

	res = aes_gcm_cipher(
		secret_key_handler,
		input,
		input_len,
		cipher_and_iv,
		&cipher_and_iv_len,
		tag,
		&tag_len,
		iv,
		iv_len,
		TEE_ALG_AES_GCM,
		TEE_MODE_ENCRYPT
	);

	if(res != TEE_SUCCESS)
		return res;
	
	TEE_MemMove(&cipher_and_iv[cipher_and_iv_len], iv, iv_len);
	TEE_Free(iv);
	return res;
}

TEE_Result derive_from_public_key(uint32_t param_types, TEE_Param params[4])
{	
	char *topic_storage_id = NULL;
	char *payload_storage_id = NULL;

	uint32_t topic_storage_id_len;
	uint32_t payload_storage_id_len;

	void *ecdh_public_x = NULL; 
	void *ecdh_public_y = NULL; 

	uint8_t *secret_key = NULL;
	uint8_t *streched_keys = NULL;
	uint8_t *topic_key = NULL;
	uint8_t *payload_key = NULL;

	uint32_t streched_keys_len = 64;
	uint32_t secret_key_len = 512;

	TEE_ObjectHandle persistent_topic_key_object_handler;
	TEE_ObjectHandle persistent_payload_key_object_handler;
	
	TEE_Result res;
	TEE_Attribute key_attr[2];
	
	TEE_Attribute topic_attr[1];
	TEE_Attribute payload_attr[1];

	uint32_t ecdh_public_keys_len;
	uint32_t key_attr_size = sizeof(key_attr)/sizeof(TEE_Attribute);

	TEE_ObjectHandle secret_key_handler;
	TEE_ObjectHandle derived_key_topic;
	TEE_ObjectHandle derived_key_payload;
	TEE_ObjectHandle derived_key;
	TEE_OperationHandle operation_handle = TEE_HANDLE_NULL;
	
	int maxKeySize = 256;
	int maxKeySizeByte = maxKeySize/8;

	uint32_t exp_param_types = TEE_PARAM_TYPES(
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT,
		TEE_PARAM_TYPE_MEMREF_INPUT
	);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;


	ecdh_public_keys_len 	= params[0].memref.size;

	topic_storage_id_len 	= params[2].memref.size;
	payload_storage_id_len	= params[3].memref.size;

	ecdh_public_x 		= TEE_Malloc(ecdh_public_keys_len, 0);
	ecdh_public_y 		= TEE_Malloc(ecdh_public_keys_len, 0);

	ecdh_public_x 		= params[0].memref.buffer;
	ecdh_public_y 		= params[1].memref.buffer;

	topic_storage_id 	= params[2].memref.buffer;
	payload_storage_id 	= params[3].memref.buffer;

	secret_key 			= TEE_Malloc(maxKeySizeByte, 0);
	topic_key 			= TEE_Malloc(maxKeySizeByte, 0);
	payload_key 		= TEE_Malloc(maxKeySizeByte, 0);
	streched_keys		= TEE_Malloc(maxKeySizeByte*2, 0);

	if (!ecdh_public_x || !ecdh_public_y || !topic_storage_id || !payload_storage_id || !secret_key || !topic_key || !payload_key || !streched_keys ) 
	{
		return TEE_ERROR_OUT_OF_MEMORY;
	} 

	res = get_key_object(mqtts_dh_storage_id, sizeof(mqtts_dh_storage_id), &secret_key_handler);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateOperation(&operation_handle, TEE_ALG_ECDH_P256, TEE_MODE_DERIVE, maxKeySize);
	if (res != TEE_SUCCESS)
		return res;

	res = TEE_SetOperationKey(operation_handle, secret_key_handler);
	if (res != TEE_SUCCESS)
		return res;	

	key_attr[0].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	key_attr[0].content.ref.buffer = ecdh_public_x;
	key_attr[0].content.ref.length = ecdh_public_keys_len;
	
	key_attr[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	key_attr[1].content.ref.buffer = ecdh_public_y;
	key_attr[1].content.ref.length = ecdh_public_keys_len;

	if(res != TEE_SUCCESS)
		return res;

	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, secret_key_len, &derived_key);
	if (res != TEE_SUCCESS)
		return res;

	//Derive Key
	TEE_DeriveKey(operation_handle, key_attr, key_attr_size, derived_key);

	res = TEE_GetObjectBufferAttribute(derived_key, TEE_ATTR_SECRET_VALUE, secret_key, &secret_key_len);
	if(res != TEE_SUCCESS)
		return res;

	//strech keys if return value is empty kdf() failed
	streched_keys = kdf(secret_key, secret_key_len, &streched_keys_len);
	if(!streched_keys)
		return TEE_ERROR_NO_DATA;

	TEE_MemMove(topic_key, streched_keys, maxKeySizeByte);
	TEE_MemMove(payload_key, streched_keys+maxKeySizeByte, maxKeySizeByte);

	topic_attr[0].attributeID = TEE_ATTR_SECRET_VALUE;
	topic_attr[0].content.ref.buffer = topic_key;
	topic_attr[0].content.ref.length = maxKeySizeByte;

	payload_attr[0].attributeID = TEE_ATTR_SECRET_VALUE;
	payload_attr[0].content.ref.buffer = payload_key;
	payload_attr[0].content.ref.length = maxKeySizeByte;
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, maxKeySize, &derived_key_topic);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_AllocateTransientObject(TEE_TYPE_GENERIC_SECRET, maxKeySize, &derived_key_payload);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_PopulateTransientObject(derived_key_topic, topic_attr, 1 );
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_PopulateTransientObject(derived_key_payload, payload_attr, 1 );
	if (res != TEE_SUCCESS)
		return res;
	//Save keys
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, topic_storage_id, topic_storage_id_len, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, derived_key_topic, NULL, 0, &persistent_topic_key_object_handler);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, payload_storage_id, payload_storage_id_len, TEE_DATA_FLAG_ACCESS_READ | TEE_DATA_FLAG_SHARE_READ, derived_key_payload, NULL, 0, &persistent_payload_key_object_handler);
	if(res != TEE_SUCCESS)
		return res;

	TEE_CloseObject(persistent_topic_key_object_handler);
	TEE_CloseObject(persistent_payload_key_object_handler);
	
	TEE_FreeTransientObject(derived_key_topic);
	TEE_FreeTransientObject(derived_key_payload);
	
	return res;
}

void* kdf(void *msk, int msk_len, uint32_t *output_keys_len)
{
	int res;
	uint8_t iv[16];
	uint8_t msg[64];
	uint32_t keysize = 256;
	void* dst;
	uint32_t dst_len = 64;

	TEE_Attribute attr;
	TEE_OperationHandle aes_ctr_operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle hkey;

	dst = TEE_Malloc(dst_len,0);

	if (!dst) 
	{
		return NULL;
	} 

	TEE_MemFill(dst, 1, dst_len);
	TEE_MemFill(msg, 1, sizeof(msg));
	TEE_MemFill(iv, 0, sizeof(iv));
	//Allocate a operation for aes_ctr with 512 BIT output key
	res = TEE_AllocateOperation(&aes_ctr_operation, TEE_ALG_AES_CTR, TEE_MODE_ENCRYPT, keysize);
	if (res != TEE_SUCCESS)
		return dst;

	res = TEE_AllocateTransientObject(TEE_TYPE_AES, keysize, &hkey);

	attr.attributeID = TEE_ATTR_SECRET_VALUE;
	attr.content.ref.buffer = msk;
	attr.content.ref.length = msk_len;

	res = TEE_PopulateTransientObject(hkey, &attr, 1);

	if(res != TEE_SUCCESS)
		return dst;
	res = TEE_SetOperationKey(aes_ctr_operation, hkey);
	if(res != TEE_SUCCESS)
		return dst;

	TEE_FreeTransientObject(hkey);

	TEE_CipherInit(aes_ctr_operation, iv, sizeof(iv));
	TEE_CipherDoFinal(aes_ctr_operation, msg, sizeof(msg), dst, &dst_len);
	*output_keys_len = dst_len;

	return dst;

}


TEE_Result verify_broker_signature(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle ecdsa_broker_key;
	TEE_Attribute key_attr[3];
	TEE_Attribute curve_attr[1];

	uint8_t *hash_out, *signature, *buffer, *ecdsa_keys, *input_x, *input_y;
	uint32_t hash_len, signature_len, buffer_len, ecdsa_keys_len, exp_param_types;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	ecdsa_keys = TEE_Malloc(64, 0);

	ecdsa_keys 		= params[0].memref.buffer; 
	ecdsa_keys_len 	= params[0].memref.size;
	buffer 			= params[1].memref.buffer; 
	buffer_len 		= params[1].memref.size; 
	signature 		= params[2].memref.buffer; 
	signature_len 	= params[2].memref.size;

	hash_out = buffer;
	hash_len = 32;

	input_x = TEE_Malloc(ecdsa_keys_len/2, 0);
	input_y = TEE_Malloc(ecdsa_keys_len/2, 0);

	TEE_MemMove(input_x, ecdsa_keys, ecdsa_keys_len/2);
	TEE_MemMove(input_y, ecdsa_keys+(ecdsa_keys_len/2), ecdsa_keys_len/2);

	curve_attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	curve_attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	curve_attr[0].content.value.b = 0;

	key_attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	key_attr[0].content.value.a = TEE_ECC_CURVE_NIST_P256;
	key_attr[0].content.value.b = 0;

	key_attr[1].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_X;
	key_attr[1].content.ref.buffer = input_x;
	key_attr[1].content.ref.length = ecdsa_keys_len/2;
	
	key_attr[2].attributeID = TEE_ATTR_ECC_PUBLIC_VALUE_Y;
	key_attr[2].content.ref.buffer = input_y;
	key_attr[2].content.ref.length = ecdsa_keys_len/2;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_PUBLIC_KEY, 256, &ecdsa_broker_key);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_PopulateTransientObject(ecdsa_broker_key, key_attr, sizeof(key_attr) / sizeof(TEE_Attribute));
	if(res != TEE_SUCCESS)
		return res;

	res = hash(TEE_ALG_SHA256, TEE_MODE_DIGEST, buffer, buffer_len, hash_out, &hash_len);
	if(res != TEE_SUCCESS)
		return res;

	// #ifdef WITH_CRYPTO_OUTPUT
		// DMSG("[CRYPTO] Verify_broker_signature: ECDSA Key used %lu\n", sizeof(ecdsa_keys) );
		// printHexValue(ecdsa_keys, ecdsa_keys_len);

		// DMSG("[CRYPTO] Verify_broker_signature: Hash to verify %i\n", hash_len);
		// printHexValue(hash_out, hash_len);

		// DMSG("[CRYPTO] Verify_broker_signature: Signature to verify %i\n", signature_len);
		// printHexValue(signature, signature_len);

		// DMSG("[CRYPTO] Verify_broker_signature: Buffer to verify signature %i\n", buffer_len);
		// printHexValue(buffer, buffer_len);
	// #endif

	res = ecc_operation(ecdsa_broker_key, TEE_MODE_VERIFY, TEE_ALG_ECDSA_P256, curve_attr, sizeof(curve_attr) / sizeof(TEE_Attribute), hash_out, hash_len, signature, &signature_len);
	if(res != TEE_SUCCESS)
		return res;

	return res;
}

TEE_Result get_broker_dsa_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	TEE_ObjectHandle broker_dsa_key;

	uint8_t ecdsa_keys[64];
	void *key_x, *key_y;
	uint32_t exp_param_types, key_len;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	key_x = TEE_Malloc(sizeof(ecdsa_keys)/2, 0);
	key_y = TEE_Malloc(sizeof(ecdsa_keys)/2, 0);

	res = get_key_object(mqtts_dsa_storage_id, sizeof(mqtts_dsa_storage_id), &broker_dsa_key);
	if (res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectBufferAttribute(broker_dsa_key, TEE_ATTR_ECC_PUBLIC_VALUE_X, key_x, &key_len);
	if(res != TEE_SUCCESS)
		return res;
	res = TEE_GetObjectBufferAttribute(broker_dsa_key, TEE_ATTR_ECC_PUBLIC_VALUE_Y, key_y, &key_len);
	if(res != TEE_SUCCESS)
		return res;

	TEE_MemMove(ecdsa_keys, key_x, key_len);
	TEE_MemMove(ecdsa_keys+key_len, key_y, key_len);

	TEE_MemMove(params[0].memref.buffer, ecdsa_keys, sizeof(ecdsa_keys));

	return res;
}

TEE_Result save_signature(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	TEE_ObjectHandle persistent_signature_obj;

	uint32_t exp_param_types;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

 	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, broker_signature_id, sizeof(broker_signature_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, params[0].memref.buffer, params[0].memref.size, &persistent_signature_obj);
	if(res != TEE_SUCCESS)
		return res;

	return res;
}


TEE_Result get_signature(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res;
	uint8_t signature[64] = {0};
	
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = get_hash(broker_signature_id, sizeof(broker_signature_id), signature, sizeof(signature));
		if(res != TEE_SUCCESS)
			return res;

	TEE_MemMove(params[0].memref.buffer, signature, sizeof(signature));

	return res;
}

void printCharValue(uint8_t* value, int size)
{
	for (int i = 0; i < size; i++)
	{
		DMSG("%c ", value[i]);
	}
}

void printHexValue(uint8_t* value, int size)
{
	for (int i = 0; i < size; i++)
	{
		DMSG("%i: %02x", i, value[i] );	
	}
}