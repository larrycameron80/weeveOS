
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <eciotify_generals.h>

#include <weeve_sockets.h>

int consumer(char *topic, int topic_len, int price, int amount)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_ECIOTIFY_UUID;
	uint32_t err_origin;

	char *device_id = NULL;
	uint32_t device_id_len = 128;

	char offer[1500];
	uint32_t offer_len = sizeof(offer);
	char command_send_demand[5000];
	char command_sub[5000];

	char *offer_output;

	pid_t program_id, pid;
	int sub_is_running;
	FILE *file;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

	device_id = malloc(device_id_len+1);

	memset(&op, 0, sizeof(op));
	memset(offer, 0, sizeof(offer));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = device_id;
 	op.params[0].tmpref.size = device_id_len;

	res = TEEC_InvokeCommand(&sess, TA_GET_DEVICE_ID, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

	memset(device_id+device_id_len, '\0', 1);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = amount;
	op.params[0].value.b = price;

	op.params[1].tmpref.buffer = NULL;
 	op.params[1].tmpref.size = 0;

 	op.params[2].tmpref.buffer = topic;
 	op.params[2].tmpref.size = topic_len;

 	op.params[3].tmpref.buffer = offer;
 	op.params[3].tmpref.size = offer_len;

	res = TEEC_InvokeCommand(&sess, TA_BLOCKCHAIN_WALLET, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",	res, err_origin);

	offer_output = malloc(offer_len+1);
	snprintf(offer_output, strlen(offer)+1, "%s", offer);

	snprintf(command_sub, 182, "mosquitto_sub -h %s -t %s/# --keysS &", BROKER_IP_LIVE, device_id);
	
	file = fopen("/bin/pid.txt", "r");
	if (file == NULL)
	{
		printf("Error opening file!\n");
	}

	fscanf(file, "%i", &pid);
	fclose(file);

	sub_is_running = kill(pid, 0);

	if (sub_is_running != 0) 
	{
		program_id = fork();
    	if ( program_id == -1 ) {
	        perror("fork failed");
	        return EXIT_FAILURE;
	    }
	    else if ( program_id == 0 ) {
	        execl("/bin/sh", "bin/sh", "-c", command_sub, NULL);
	        return EXIT_FAILURE;
	    }

	    int status;
	    if ( waitpid(program_id, &status, 0) == -1 ) {
	        perror("waitpid failed");
	        return EXIT_FAILURE;
	    }
		file = fopen("/bin/pid.txt", "w");
		if (file == NULL)
		{
			printf("Error opening file!\n");
		}

		fprintf(file, "%i", program_id+1);
		fclose(file);
		printf("Subscribed to Device-Channel\n");
	}

	sprintf(command_send_demand, "mosquitto_pub -h %s -t %s/%s/demand -m %s --keysP", BROKER_IP_LIVE, topic, device_id, offer_output);
	system(command_send_demand);
	
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	
	return res;
}

int producer(char *topic, int topic_len, int price, int amount, void *data, int data_len)
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_ECIOTIFY_UUID;
	uint32_t err_origin;

	char offer[5000];
	char command_sub[5000];
	char command_send_offer[5000];

	uint32_t offer_len = sizeof(offer);

	char *device_id = NULL;
	uint32_t device_id_len = 128;

	char *offer_output;

	pid_t program_id, pid;
	int sub_is_running;
	FILE *file;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, err_origin);

	device_id = malloc(device_id_len+1);

	memset(&op, 0, sizeof(op));
	memset(offer, 0, sizeof(offer));

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = device_id;
 	op.params[0].tmpref.size = device_id_len;

	res = TEEC_InvokeCommand(&sess, TA_GET_DEVICE_ID, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

	memset(device_id+device_id_len, '\0', 1);

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT);
	op.params[0].value.a = amount;
	op.params[0].value.b = price;

	op.params[1].tmpref.buffer = data;
 	op.params[1].tmpref.size = data_len;

 	op.params[2].tmpref.buffer = topic;
 	op.params[2].tmpref.size = topic_len;

 	op.params[3].tmpref.buffer = offer;
 	op.params[3].tmpref.size = offer_len;

	res = TEEC_InvokeCommand(&sess, TA_BLOCKCHAIN_WALLET, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",	res, err_origin);

	offer_output = malloc(offer_len+1);
	snprintf(offer_output, strlen(offer)+1, "%s", offer);

	snprintf(command_sub, 182, "mosquitto_sub -h %s -t %s/# --keysS &", BROKER_IP_LIVE, device_id);

	file = fopen("/bin/pid.txt", "r");
	if (file == NULL)
	{
		printf("Error opening file!\n");
	}

	fscanf(file, "%i", &pid);

	fclose(file);

	sub_is_running = kill(pid, 0);

	if (sub_is_running != 0) 
	{
		program_id = fork();
    	if ( program_id == -1 ) {
	        perror("fork failed");
	        return EXIT_FAILURE;
	    }
	    else if ( program_id == 0 ) {
	        execl("/bin/sh", "bin/sh", "-c", command_sub, NULL);
	        return EXIT_FAILURE;
	    }

	    int status;
	    if ( waitpid(program_id, &status, 0) == -1 ) {
	        perror("waitpid failed");
	        return EXIT_FAILURE;
	    }
		file = fopen("/bin/pid.txt", "w");
		if (file == NULL)
		{
			printf("Error opening file!\n");
		}

		fprintf(file, "%i", program_id+1);
		fclose(file);
		printf("Subscribed to Device-Channel\n");
	}

	sprintf(command_send_offer, "mosquitto_pub -h %s -t %s/%s/supply -m %s --keysP", BROKER_IP_LIVE, topic, device_id, offer_output);
	system(command_send_offer);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return res;
}