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
#include <ta_common.h>
#include <cmd_invoke.h>
#include <eciotify_generals.h>
#include <eciotify_ta.h>


/**
*	Entry point to chose which function to call on which command 
*	Normal world call this function with a command and secure world maps command to function
*/
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx, uint32_t cmd_id, uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	DMSG("[TA] Entry Point, chossing TA methode");
	switch (cmd_id) {
	case TA_HELLO_WORLD_CHECK_MEMORY_REGION:
		return check_memory_region(param_types, params);
	case TA_GEN_WALLET_KEYS:
		return gen_bc_key();
	case TA_GEN_TESTIMONY_KEYS:
		return gen_keys();
	case TA_BLOCKCHAIN_WALLET:
		return blockchain_wallet(param_types, params);
	case TA_GEN_MQTTS_KEYS:
		return create_credential_keys(param_types);
	case TA_REGISTER_DEVICE:
		return register_device(param_types, params);
	case TA_HELLO_WORLD_CMD_GET_ECDSA_KEYS:
		return return_ecdsa_keys(param_types, params);
	case TA_HELLO_WORLD_CMD_GET_ECDH_KEYS:
		return return_ecdh_keys(param_types, params);
	case TA_HELLO_WORLD_CMD_OBJ_SIGN_KEYS:
		return return_sign_keys(param_types, params);
	case TA_HELLO_WORLD_CMD_OBJ_ENCRYPT:
		return aes128_gcm_encrypt(param_types, params);
	case TA_HELLO_WORLD_CMD_OBJ_DECRYPT:
		return aes128_gcm_decrypt(param_types, params);
	case TA_HELLO_WORLD_CMD_VERIFY_SIGN: 
		return verify_signature(param_types, params);
	case TA_HELLO_WORLD_CMD_DERIVE_KEY:
		return derive_from_public_key(param_types, params);
	case TA_HELLO_WORLD_CMD_DELETE_PERS_OBJ:
		return delete_persistent_object(param_types, params);
	case TA_SAVE_BC_KEYS:
		return save_bc_keys(param_types, params);
	case TA_GET_DEVICE_ID:
		return get_device_id(param_types, params);
	case TA_DEL_KEYS:
		return del_keys();
	case TA_VERIFY_BROKER_SIG:
		return verify_broker_signature(param_types, params);
	case TA_GET_BROKER_DSA_KEY:
		return get_broker_dsa_key(param_types, params);
	case TA_SAVE_SIGNATURE:
		return save_signature(param_types, params);
	case TA_GET_SIGNATURE:
		return get_signature(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}