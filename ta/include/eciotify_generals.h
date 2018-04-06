#ifndef TA_ECIOTIFY_GENERALS_H
#define TA_ECIOTIFY_GENERALS_H
//SHARED TO NORMAL WORLD


/* This UUID is generated with uuidgen
   the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html */

#define TA_ECIOTIFY_UUID { 0xba5b4f4d, 0xb08a, 0x4574, \
{ 0xb7, 0x68, 0x6c, 0x74, 0xc3, 0x9d, 0x32, 0x93} }


#define BROKER_IP_DEV "test.weeve.network"
#define BROKER_IP_LIVE "dev.weeve.network"

/***********************************************/
/***********************************************/
#define TA_GEN_MQTTS_KEYS						1
#define TA_GEN_TESTIMONY_KEYS					2
#define TA_GEN_WALLET_KEYS						3
#define TA_REGISTER_DEVICE						4
#define TA_SAVE_BC_KEYS							5
/***********************************************/		
/***********************************************/
#define TA_HELLO_WORLD_CHECK_MEMORY_REGION 		6
#define TA_BLOCKCHAIN_WALLET					7
/***********************************************/
/***********************************************/
#define TA_HELLO_WORLD_CMD_OBJ_ECDSA			8
#define TA_HELLO_WORLD_CMD_OBJ_ECDH				9
#define TA_HELLO_WORLD_CMD_OBJ_GET_SIGN_KEYS 	10
#define TA_HELLO_WORLD_CMD_OBJ_ENCRYPT			11
#define TA_HELLO_WORLD_CMD_OBJ_DECRYPT			12
#define TA_HELLO_WORLD_CMD_CREATE_CREDENTIAL 	13
#define TA_HELLO_WORLD_CMD_GET_ECDSA_KEYS	 	14
#define TA_HELLO_WORLD_CMD_GET_ECDH_KEYS		15
#define TA_HELLO_WORLD_CMD_OBJ_SIGN_KEYS 		16
#define TA_HELLO_WORLD_CMD_VERIFY_SIGN			17
#define TA_HELLO_WORLD_CMD_DERIVE_KEY			18
#define TA_HELLO_WORLD_CMD_DELETE_PERS_OBJ		19
#define TA_GET_DEVICE_ID						20
/***********************************************/
#define	TA_DEL_KEYS								21
/***********************************************/
#define TA_VERIFY_BROKER_SIG					22
#define TA_GET_BROKER_DSA_KEY					23
#define TA_SAVE_SIGNATURE						24
#define TA_GET_SIGNATURE						25

/*
 * Supported algorithms
 */
#define TA_SHA_SHA1	0

#endif /*TA_ECIOTIFY_GENERALS_H*/