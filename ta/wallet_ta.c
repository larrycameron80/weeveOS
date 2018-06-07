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
#include <wallet_ta.h>
#include <eciotify_ta.h>
#include <string.h>

#define RLP_MAX 1024
#define WITHOUT_SIGN 0 
#define WITH_SIGN 1


//CHANGE NAME
char eth_keys_id[] = {'D', 'S', 'A', 'P', 'U', 'B', 'B', 'C'};

char eth_priv_key_idA[] = {'D', 'S', 'A', 'P', 'R', 'V', 'B', 'C'};
char eth_addr_key_idA[] = {'E', 'T', 'H', 'A', 'D', 'D', 'R', 'E', 'S', 'S'};
int chain_id = 0;

/*
	Basic functionallity
	1) call TA code with: create_transcation() and give hex_string to TA
	2) [verify the hex_string with gateway]
	3) parse the JSON string
	4) create the transaction -> tx_str
	5) sign the transaction and add them to tx_str -> tx_str_sign
	6) Create a hex_string from tx_str_sign and return the value
*/

struct supply_structure
{
	const char *topic;
	const char *tid;
	const char *supply_bc_address;
	const char *demand_bc_address;
	const char *bc_nonce;
	const char *date;
	const char *currency;
	const char *price;
	const char *amount;
	const char *value;
	const char *testimony;
	const char *testimony_signature;
	const char *gasLimit; 
	const char *gasPrice; 
	const char *v; /* CHAIN_ID */
	const char *r; /* 0-64 Byte from signature */
	const char *s; /* 65-128 Byte from signature */
};


void hex2bin(const char* src, char* target);
int char2int(char input);
void parse_json(struct supply_structure *supply, const char *json_string);
char* encode_transaction(struct supply_structure *supply, int *transaction_len, int with_sign, char* signature);
char *rlp_encode(const char *input, int input_len, int *output_len);
char to_binary(int x);
char* rlp_encode_length(int len, int offset, int *allocated_memory);
char* string_rlp_encode(const char* src, int src_len, int *dst_len);
char* hex_string_rlp_encode(const char* src, int src_len, int *dst_len);
char get_last_byte_from_y_pub_key(void);
char* parse_value_from_json(const char* key, const char* input, int *out_len);
int hex2int(const char *hex);
char *strstr(const char *s1, const char *s2);

char *strstr(const char *s1, const char *s2)
{
	size_t l1, l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	l1 = strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}


/**
*	Search for a key in a json string and return its value
**/
char* parse_value_from_json(const char* key, const char* input, int *out_len)
{
	char *ret;
	char *result = NULL;
	ret = strstr(input, key);
	if(ret)
	{
		ret = strstr(ret, "':'");
		if(ret)
		{
			//int i = 3 to skip "';'"
			for(int i = 3; ret[i] != '\''; i++)
			{
				*out_len = i-2;	
			}
			result = TEE_Malloc((*out_len+1)*sizeof(char), TEE_MALLOC_FILL_ZERO);
			TEE_MemMove(result, ret+3, *out_len);
			result[*out_len] = '\0';
		}
	}

	if(!result)
		return NULL;
	else 
		return result;
}

/**
*	Pass a allocated supply_structure and the json_string to parse
*	Function will fill up the supply_structure 
**/
void parse_json(struct supply_structure *supply, const char *json_string) 
{	
	int out_len = 0;
	supply->topic = parse_value_from_json("topic", json_string, &out_len); 
	supply->tid = parse_value_from_json("tid", json_string, &out_len);
	supply->supply_bc_address = parse_value_from_json("supply_bc_address", json_string, &out_len);
	supply->demand_bc_address = parse_value_from_json("demand_bc_address", json_string, &out_len);
	supply->bc_nonce = parse_value_from_json("bc_nonce", json_string, &out_len);
	supply->date = parse_value_from_json("date", json_string, &out_len);
	supply->currency = parse_value_from_json("currency", json_string, &out_len);
	supply->price = parse_value_from_json("price", json_string, &out_len);
	supply->amount = parse_value_from_json("amount", json_string, &out_len);
	supply->testimony = parse_value_from_json("testimony", json_string, &out_len);
	supply->testimony_signature = parse_value_from_json("testimony_signature", json_string, &out_len);
	supply->value = parse_value_from_json("value", json_string, &out_len);
	supply->gasLimit = parse_value_from_json("gas_limit", json_string, &out_len);
	supply->gasPrice = parse_value_from_json("gas_price", json_string, &out_len);
	supply->v = parse_value_from_json("chain_id", json_string, &out_len);
	supply->r = "00";
	supply->s = "00";

	chain_id = hex2int(supply->v);

}


TEE_Result create_transaction(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_param_types;
	const char* json_string = "{'topic':'electricity','tid':'fe3d61b7cd6eff03698c0303b056e0fe3116206e','supply_bc_address':'f125691d24a6b5cdcb87a89cb825fdf4487c2a34','demand_bc_address':'f125691d24a6b5cdcb87a89cb825fdf4487c2a34','bc_nonce':'00','date':1524140611,'currency':'ETH','price':'1','amount':'1','value':'e8d4a51000','gas_price':'3b9aca00','gas_limit':'0186a0','chain_id':'0539','testimony':'c1766772be44d7b418afb11d6ec9027a3bad38b1','testimony_signature':'41278e5fd5b68a0d7697f232451fe26afe793dab3faf802ea598a539807c71fab8b5e3dbf0a095dcdf1988113577e8dd27c31a5ec03e7b16fa8eec53d0bb2210'}";
	struct supply_structure supply;
	
	char* signature = NULL;
	uint32_t signature_len = 0;
	char* transaction = NULL;
	
	int transaction_len = 0;

	exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)params;

	/* Parse the JSON String to our Structure and encode the transaction without the signature */
	parse_json(&supply, json_string);
	transaction = encode_transaction(&supply, &transaction_len, WITHOUT_SIGN, NULL);

	// DMSG("First transaction: %i", transaction_len);
	// for (int i = 0; i < transaction_len; ++i)
	// {
	// 	DMSG("%02x", transaction[i]);
	// }
 
	signature = sign_transaction(transaction, transaction_len, &signature_len);
	if(!signature)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* encode with signature again */
	TEE_Free(transaction);
	transaction_len = 0;
	transaction = encode_transaction(&supply, &transaction_len, WITH_SIGN, signature);

	// DMSG("Final transaction: %i", transaction_len);
	// for (int i = 0; i < transaction_len; ++i)
	// {
	// 	DMSG("%02x", transaction[i]);
	// }

	TEE_MemMove(params[1].memref.buffer, transaction, transaction_len);
	params[1].memref.size = transaction_len;

	TEE_Free(signature);
	return res;
}

char* hex_string_rlp_encode(const char* src, int src_len, int *dst_len)
{
	char* dst = NULL;
	
	char inp [src_len];
	char dest [sizeof(inp)/2];
	TEE_MemMove(inp, src, src_len);
	hex2bin(inp, dest);

	dst = rlp_encode(dest, sizeof(dest), dst_len);
	if(!dst) 
	{
		TEE_Free(dst);
		return NULL;
	}
	return dst;
}

char* string_rlp_encode(const char* src, int src_len, int *dst_len)
{
	char* dst = NULL;
	
	dst = rlp_encode(src, src_len, dst_len);
	if(!dst) 
	{
		TEE_Free(dst);
		return NULL;
	}
	return dst;
}

/**
*	If we pass the WITH_SIGN argument with 1 we need to provide the signature
*	else we can just pass NULL there.
**/

char* encode_transaction(struct supply_structure *supply, int *transaction_len, int with_sign, char* signature)
{
	char* prefix_transaction = NULL;
	int prefix_transaction_len = 0;

	char* encoded_transaction = NULL;
	char* result_transaction = NULL;
	
	char* to = NULL;
	int to_len = 0;

	char* data = NULL;
	int data_len = 0;

	char* value = NULL;
	int value_len = 0;

	char* gas_limit = NULL;
	int gas_limit_len = 0;

	char* gas_price = NULL;
	int gas_price_len = 0;

	char* nonce = NULL;
	int nonce_len = 0;

	
	/* JUST NEED IF WE CALCUATE WITH SIGNATURE */
	char* v = NULL;
	int v_len = 0;

	char* r = NULL;
	int r_len = 0;

	char* s = NULL;
	int s_len = 0;

	char* signature_y = NULL;
	char* signature_x = NULL;
	int signature_point_len = 32;
	int recoveryId;
	char *recoveryId_hex;
	int recoveryId_hex_len = 3;

	/* JUST NEED IF WE CALCUATE WITH SIGNATURE */

	/* loop through all struct members */
	to = hex_string_rlp_encode(supply->supply_bc_address,strlen(supply->supply_bc_address), &to_len );
	data = hex_string_rlp_encode(supply->tid,strlen(supply->tid), &data_len );

	value = hex_string_rlp_encode(supply->value, strlen(supply->value), &value_len);
	gas_price = hex_string_rlp_encode(supply->gasPrice, strlen(supply->gasPrice),&gas_price_len);
	gas_limit = hex_string_rlp_encode(supply->gasLimit, strlen(supply->gasLimit), &gas_limit_len);
	nonce = hex_string_rlp_encode(supply->bc_nonce, strlen(supply->bc_nonce), &nonce_len);
	
	if(with_sign && signature)
	{
		signature_y = (char*) TEE_Malloc(signature_point_len*sizeof(char), TEE_MALLOC_FILL_ZERO);
		signature_x = (char*) TEE_Malloc(signature_point_len*sizeof(char), TEE_MALLOC_FILL_ZERO);

		TEE_MemMove(signature_x, signature, signature_point_len);
		TEE_MemMove(signature_y, signature+signature_point_len, signature_point_len);
			

		// 2B => CHAIN ID 4 (43)
		// 0A95 => CHAIN ID 1337
		// chainID * 2 + 35 + RecoveryID
		/*
		id = y1 & 1; // Where (x1,y1) = k x G;
		if (s > curve.n / 2) id = id ^ 1; // Invert id if s of signature is over half the n
		4*2+35+1
			
		v = 27 || v = 28 => this is the last bit from y_pub_key
		*/
		recoveryId = chain_id*2+35+(get_last_byte_from_y_pub_key() & 1);
		if(recoveryId > 0xFF)
		{
			recoveryId_hex_len = 5;
		}
		recoveryId_hex = TEE_Malloc(recoveryId_hex_len, TEE_MALLOC_FILL_ZERO);
		// DMSG("RecoveryID %i (in hex %x) (last bit is %i) ", recoveryId, recoveryId, get_last_byte_from_y_pub_key() & 1);
		snprintf(recoveryId_hex, recoveryId_hex_len, "%02x", recoveryId);
		
		//If we miss a leading 0
		if((int)strlen(recoveryId_hex) != recoveryId_hex_len-1)
		{
			TEE_Free(recoveryId_hex);
			recoveryId_hex[0] = '0';
			snprintf(recoveryId_hex+1, recoveryId_hex_len, "%02x", recoveryId);
		}

		v = hex_string_rlp_encode(recoveryId_hex, recoveryId_hex_len-1, &v_len );
		r = string_rlp_encode(signature_x, signature_point_len, &r_len);
		s = string_rlp_encode(signature_y, signature_point_len, &s_len);
	}
	else
	{
		(void)signature;
		v = hex_string_rlp_encode(supply->v, strlen(supply->v), &v_len );
		r = hex_string_rlp_encode(supply->r, strlen(supply->r), &r_len );
		s = hex_string_rlp_encode(supply->s, strlen(supply->s), &s_len );		 
	}

	*transaction_len = to_len 
		+ data_len
		+ value_len
		+ gas_price_len
		+ gas_limit_len
		+ nonce_len
		+ v_len
		+ r_len
		+ s_len
	;

	encoded_transaction = (char*) TEE_Malloc((*transaction_len)*sizeof(char), TEE_MALLOC_FILL_ZERO);
	if(!encoded_transaction)
	{
		return NULL;
	}
	
	/* Concate all pointer (struct members) to the transaction */
	/* ATTANTION ORDER NEED TO BE VALID: nonce;price;limit;to;value;data*/
	TEE_MemMove(encoded_transaction, nonce, nonce_len);
	TEE_MemMove(encoded_transaction+nonce_len, gas_price, gas_price_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len, gas_limit, gas_limit_len);
	
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len, to, to_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len+to_len, value, value_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len+to_len+value_len, data, data_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len+to_len+value_len+data_len, v, v_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len+to_len+value_len+data_len+v_len, r, r_len);
	TEE_MemMove(encoded_transaction+nonce_len+gas_price_len+gas_limit_len+to_len+value_len+data_len+v_len+r_len, s, s_len);
	
	

	if(with_sign && signature)
	{
		TEE_Free(signature_x);
		TEE_Free(signature_y);
	}

	/* Free everything */
	TEE_Free(to);
	TEE_Free(data);
	TEE_Free(value);
	TEE_Free(gas_price);
	TEE_Free(gas_limit);
	TEE_Free(nonce);
	TEE_Free(v);
	TEE_Free(r);
	TEE_Free(s);
	

	/* 	
		Calculate the total length with rlp encode. 
		192 => 0xC0
	*/
	prefix_transaction = rlp_encode_length(*transaction_len, 192, &prefix_transaction_len);
	result_transaction = (char*) TEE_Malloc((*transaction_len+prefix_transaction_len)*sizeof(char), TEE_MALLOC_FILL_ZERO);
	if(!result_transaction)
		return NULL;

	TEE_MemMove(result_transaction, prefix_transaction, prefix_transaction_len);
	TEE_MemMove(result_transaction+prefix_transaction_len, encoded_transaction, *transaction_len);
	*transaction_len = *transaction_len+prefix_transaction_len;
	
	TEE_Free(prefix_transaction);

	return result_transaction;
}

char get_last_byte_from_y_pub_key(void)
{
	TEE_Result res;
	TEE_ObjectHandle ecdsa_keys;

	char *eth_pub_point_y = NULL;
	uint32_t pub_point_len = 32;
	char result_byte = '\0';

	eth_pub_point_y = TEE_Malloc(pub_point_len, 0);

	if(!eth_pub_point_y)
	{
		return '\0';
	}

	res = get_key_object(&eth_keys_id, sizeof(eth_keys_id), &ecdsa_keys);
	if(res != TEE_SUCCESS )
		return '\0';	

	res = TEE_GetObjectBufferAttribute(ecdsa_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, eth_pub_point_y, &pub_point_len);
	if(res != TEE_SUCCESS)
		return '\0';

	result_byte = eth_pub_point_y[pub_point_len-1];

	TEE_Free(eth_pub_point_y);
	TEE_CloseObject(ecdsa_keys);
	return result_byte;

}

/**
*	Return the signature for a given transaction. 
* 	Process: takes the transaction as input, hash it (keccak) and calculate the signature 
**/
char* sign_transaction(char *transaction, int transaction_len, uint32_t *signature_len)
{
	TEE_OperationHandle operation = TEE_HANDLE_NULL;
	TEE_ObjectHandle ecdsa_keys;
	TEE_Result res;
	TEE_OperationHandle hash_op = TEE_HANDLE_NULL;
		
	char* signature = NULL;
	void* transaction_hash; 
	uint32_t transaction_hash_len = 500; 
	*signature_len = 500;

	signature = (char*) TEE_Malloc((*signature_len)*sizeof(char), TEE_MALLOC_FILL_ZERO);
	transaction_hash = TEE_Malloc(transaction_hash_len, TEE_MALLOC_FILL_ZERO );

	if(!signature)
		return NULL;

	res = get_key_object(&eth_keys_id, sizeof(eth_keys_id), &ecdsa_keys);
	if(res != TEE_SUCCESS )
		return NULL;
	
	res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA3_KECCAK, TEE_MODE_DIGEST, 0);
	if(res != TEE_SUCCESS)
		return NULL;

	res = TEE_DigestDoFinal(hash_op, transaction, transaction_len, transaction_hash, &transaction_hash_len);
	if(res != TEE_SUCCESS)
		return NULL;

	res = TEE_AllocateOperation(&operation, TEE_ALG_ECDSA_P256, TEE_MODE_SIGN, 256);
	if (res != TEE_SUCCESS)
		return NULL;

	res = TEE_SetOperationKey(operation, ecdsa_keys);
	if (res != TEE_SUCCESS)
		return NULL;

	res = TEE_AsymmetricSignDigest(
		operation, 
		NULL, 
		0,
		transaction_hash, 
		transaction_hash_len, 
		signature, 
		signature_len
	);

	if(res != TEE_SUCCESS)
		return NULL;

	// DMSG("SIGNATURE: %i ", (int) *signature_len);
	// for (int i = 0; i < (int) *signature_len; i++)
	// {
	// 	DMSG("%02x", signature[i]);
	// }
	// DMSG("==========================================================");
	// DMSG("DATA: %i ", (int) transaction_hash_len);
	// for (int i = 0; i < (int) transaction_hash_len; i++)
	// {
	// 	DMSG("%02x", *( (char*)transaction_hash+i));
	// }
	// DMSG("==========================================================");

	TEE_Free(transaction_hash);
	TEE_FreeOperation(operation);
	TEE_FreeOperation(hash_op);
	
	return signature;
}

TEE_Result generate_wallet_keys(void)
{
	TEE_Attribute eth_attr[1];
	TEE_Result res;
	TEE_ObjectHandle eth_keys;
	TEE_ObjectHandle persistent_eth_keys_obj;	
	
	uint32_t eth_attr_size = 1;
	uint32_t pub_point_len = 32;

	int eth_max_key_size = 256;

	char *eth_pub_point_x = NULL;
	char *eth_pub_point_y = NULL;
	char *eth_pub_key = NULL;
	// char *eth_private = NULL;

	eth_pub_point_x = TEE_Malloc(pub_point_len, 0);
	eth_pub_point_y = TEE_Malloc(pub_point_len, 0);
	eth_pub_key 	= TEE_Malloc(pub_point_len*2, 0);
	// eth_private		= TEE_Malloc(pub_point_len, 0);

	if(!eth_pub_point_x || !eth_pub_point_y || !eth_pub_key)
	{
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	eth_attr[0].attributeID = TEE_ATTR_ECC_CURVE;
	eth_attr[0].content.value.a = TEE_ECC_CURVE_SEC_P256K1;
	eth_attr[0].content.value.b = 0;

	res = TEE_AllocateTransientObject(TEE_TYPE_ECDSA_KEYPAIR, eth_max_key_size, &eth_keys);
	if(res != TEE_SUCCESS)
		return res;
	res = TEE_GenerateKey(eth_keys, eth_max_key_size, eth_attr, eth_attr_size);
	if(res != TEE_SUCCESS)
		return res;


	res = TEE_GetObjectBufferAttribute(eth_keys, TEE_ATTR_ECC_PUBLIC_VALUE_X, eth_pub_point_x, &pub_point_len);
	if(res != TEE_SUCCESS)
		return res;

	res = TEE_GetObjectBufferAttribute(eth_keys, TEE_ATTR_ECC_PUBLIC_VALUE_Y, eth_pub_point_y, &pub_point_len);
	if(res != TEE_SUCCESS)
		return res;

	// (void)eth_private;
	// res = TEE_GetObjectBufferAttribute(eth_keys, TEE_ATTR_ECC_PRIVATE_VALUE, eth_private, &pub_point_len);
	// if(res != TEE_SUCCESS)
	// 	return res;

	// DMSG("Public_x:");
	// for (int i = 0; i < (int) pub_point_len; i++)
	// {
	// 	DMSG("%02x", *(eth_pub_point_x+i) );
	// }

	// DMSG("Public_y:");
	// for (int i = 0; i < (int) pub_point_len; i++)
	// {
	// 	DMSG("%02x", *(eth_pub_point_y+i) );
	// }

	// DMSG("Private:");
	// for (int i = 0; i < (int) pub_point_len; i++)
	// {
	// 	DMSG("%02x", *(eth_private+i) );
	// }
	
	//Create the public key
	TEE_MemMove(eth_pub_key, eth_pub_point_x, pub_point_len);
	TEE_MemMove(eth_pub_key+pub_point_len, eth_pub_point_y, pub_point_len);

	// Calculate and save the address
	res = generate_address(eth_pub_key, pub_point_len*2);
	if(res != TEE_SUCCESS)
		return res;

	//save keys to secure storage
	//Eth key
 	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, eth_keys_id, sizeof(eth_keys_id), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, eth_keys, NULL, 0, &persistent_eth_keys_obj);
	if(res != TEE_SUCCESS)
		return res;

	TEE_CloseObject(persistent_eth_keys_obj);
	TEE_FreeTransientObject(eth_keys);
	TEE_Free(eth_pub_point_x);
	TEE_Free(eth_pub_point_y);
	TEE_Free(eth_pub_key);


	return res;
}

TEE_Result generate_address(void *eth_public_key, uint32_t eth_public_key_size)
{
	TEE_Result res;
	TEE_ObjectHandle persistent_eth_addr_obj;
	
	int eth_address_size = 20;
	char eth_address[eth_address_size];
	char *eth_address_hex;

	char *out;
	uint32_t outsz = 0;
	TEE_OperationHandle hash_op = TEE_HANDLE_NULL;

	eth_address_hex = (char*) TEE_Malloc((eth_address_size*2)*sizeof(char), TEE_MALLOC_FILL_ZERO);
	//@TODO useless cause outsz = 0;
	out = (char*) TEE_Malloc(outsz*sizeof(char), TEE_MALLOC_FILL_ZERO);

	if(!out || !eth_address_hex)
	{
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	
	res = TEE_AllocateOperation(&hash_op, TEE_ALG_SHA3_KECCAK, TEE_MODE_DIGEST, 0);
	if(res != TEE_SUCCESS)
		return res;

	out = eth_public_key;
	outsz = 32;

	res = TEE_DigestDoFinal(hash_op, eth_public_key, eth_public_key_size, out, &outsz);
	if(res != TEE_SUCCESS)
		return res;

	for (int c = 0, h = outsz-eth_address_size ; c < eth_address_size; c++, h++)
	{
		eth_address[c] = *(out+h);
	}

	// DMSG("Size ADDR: (int) %i", eth_address_size );
	// for (int i = 0; i < eth_address_size; i++)
	// {
	// 	DMSG("HASH: %02x", eth_address[i] );
	// }

	//create a string from the eth_address that holds the hex representation
	for (int i = 0; i < eth_address_size; i++)
	{
		snprintf(eth_address_hex+i*2, eth_address_size*2, "%02x", eth_address[i]);
	}
	
	//save address (hex representation) in secure storage
	//Eth address
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE, eth_addr_key_idA, sizeof(eth_addr_key_idA), TEE_DATA_FLAG_SHARE_READ | TEE_DATA_FLAG_ACCESS_WRITE, TEE_HANDLE_NULL, eth_address_hex, eth_address_size*2, &persistent_eth_addr_obj);
	if(res != TEE_SUCCESS)
		return res;

	TEE_CloseObject(persistent_eth_addr_obj);
	// TEE_Free(eth_address_hex);
	// TEE_Free(out);
	return res;

}



/*========================== rlp HELPER FUNCTIONS ==========================*/
char to_binary(int x)
{
    if (x == 0)
        return '\0';
    else
        return to_binary( (int) (x/256) ) + (x % 256);
}

/**
*	Define the prefix for strings in rlp encoding
**/
char* rlp_encode_length(int len, int offset, int *allocated_memory )
{
	char* result = NULL;
	char binary_len;
    if (len < 56)
    {
    	*allocated_memory = 1;
    	result = (char*) TEE_Malloc((*allocated_memory)*sizeof(char), TEE_MALLOC_FILL_ZERO);
    	if(!result)
    		return NULL;
    	result[0] = len+offset;
    }
    /* string is longer then 56 byte and smaller than RLP_MAX (should be 256^8 but this is way too much and an unneeded calculation)*/
    else if(len < RLP_MAX)
    {
    	*allocated_memory = 2;
     	result = (char*) TEE_Malloc((*allocated_memory)*sizeof(char), TEE_MALLOC_FILL_ZERO);

     	if(!result)
     		return NULL;
        binary_len = to_binary(len);

     	result[0] = sizeof(binary_len) + offset + 55;
		result[1] = binary_len;
    }
    /* Something else happend => ERROR */
    else
    {
        result = NULL;
    }
    return result;

}

/**
*	case 1 byte is between 0x00 - 0x7f (a ascii symbole):
*		return is the byte value
*
*	case the length of the string is between 0 - 55 byte long:
*		return 0x80+len(string) ++ string
*
*	case the length of the string is between 56 and 256^8:
*		return 0xb7+len(binary(string))+len(string) ++ string
*
* 	return a pointer to the string + prefix and set the output_len to the length of that pointer
**/
char *rlp_encode(const char *input, int input_len, int *output_len)
{
	char* result = NULL;
	char* encoded_length = NULL;
	int encoded_length_size = 0;

	/* just return the value as encode string */
    if(input_len == 1 && (input[0] < 0x80))
    {	
    	*output_len = 1;
    	if(input[0] == 0x00)
    	{
    		result = TEE_Malloc(input_len*sizeof(char), TEE_MALLOC_FILL_ZERO);
    		result[0] = 0x80;
    	}
    	else
    	{
    		result = TEE_Malloc(input_len*sizeof(char), TEE_MALLOC_FILL_ZERO);
    		TEE_MemMove(result, input, input_len);	
    	}
    	
        return result;
    }

    /* we have a string, check length */
    else 
    {
    	encoded_length = rlp_encode_length(input_len, 0x80, &encoded_length_size); 
    	/* An error occure while calculation the prefix */
    	if(!encoded_length || encoded_length_size == 0 || encoded_length_size > 2)
    		return NULL;
    	
    	/* Allocate the length of the string + the needed prefix size */
    	result = (char*) TEE_Malloc(sizeof(char)*(input_len+encoded_length_size), TEE_MALLOC_FILL_ZERO);
    	
    	/* Our string is between 0 and 55 long */
    	if(encoded_length_size == 1)
    	{
    		result[0] = encoded_length[0];
    	}
    	/* Our string length is over 56 and under RLP_MAX*/
    	else if(encoded_length_size == 2)
    	{
    		result[0] = encoded_length[0];
    		result[1] = encoded_length[1];
    	}
    	/* This should not happen and should be covered from 'if(!encoded_length) return NULL;' if we still get here return => ERROR */
    	else 
    	{
    		TEE_Free(encoded_length);
	    	return NULL;
    	}

    	*output_len = input_len+encoded_length_size;
    	TEE_MemMove(result+encoded_length_size, input, input_len);
		TEE_Free(encoded_length);
        return result;
    }
}

int char2int(char input)
{
	if(input >= '0' && input <= '9')
		return input - '0';
	if(input >= 'A' && input <= 'F')
		return input - 'A' + 10;
  	if(input >= 'a' && input <= 'f')
    	return input - 'a' + 10;
	else 
		return 0;

}
void hex2bin(const char* src, char* target)
{
  while(*src && src[1])
  {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}

int hex2int(const char *hex) 
{
    int val = 0;
    while (*hex) {
        // get current character then increment
        uint8_t byte = *hex++; 
        // transform hex character to the 4bit equivalent number, using the ascii table indexes
        if (byte >= '0' && byte <= '9') byte = byte - '0';
        else if (byte >= 'a' && byte <='f') byte = byte - 'a' + 10;
        else if (byte >= 'A' && byte <='F') byte = byte - 'A' + 10;    
        // shift 4 to make space for new digit, and add the 4 bits of the new digit 
        val = (val << 4) | (byte & 0xF);
    }
    return val;
}