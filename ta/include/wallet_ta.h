#ifndef TA_WALLET_H
#define TA_WALLET_H

#include <ta_common.h>

TEE_Result generate_wallet_keys(void);
TEE_Result generate_address(void *eth_public_key, uint32_t eth_public_key_size);
TEE_Result create_transaction(uint32_t param_types, TEE_Param params[4]);
char* sign_transaction(char *transaction, int transaction_len, uint32_t *signature_len);
#endif /*TA_CONTROL_H*/