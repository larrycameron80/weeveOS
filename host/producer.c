
#include <err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <termios.h>
#include <assert.h>
#include <sys/wait.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <eciotify_generals.h>
#include <weeve_sockets.h>

TEEC_Result start_ta_context();
void stop_ta_context();
int start_producer();
int getch(void);
void * get_pc () {return __builtin_return_address(0);}
char *broker_ip = BROKER_IP_LIVE;

TEEC_Context ctx;
TEEC_Session sess;

int main(int argc, char *argv[])
{
	printf("###### Producer Client ######\n");
	if(argc > 1)
	{
		if(!strcmp(argv[1], "-d") || !strcmp(argv[1], "--dev"))
		{
			broker_ip = BROKER_IP_DEV;
		}
	}
	start_producer();
	return 0;
}

int start_producer()
{
	TEEC_Result res;
	TEEC_Operation op;
	uint32_t err_origin;
	void *startFor, *endFor, *startMeasure, *endMeasure, *startInput, *endInput;
	int differenceInBytes;
	char* topic = "electricity";
	int topic_len = strlen(topic);

	char* data = "test_data";
	int data_len  = strlen(data);

	int counter = 1;
	int j = 0;
	int z = 0;
	int k = 0;
	int amountT;
	int priceT;
	int character;

	TEEC_SharedMemory in_shm = {
		.flags = TEEC_MEM_INPUT
	};

	res = start_ta_context();
	if (res == TEEC_SUCCESS)
		printf("[NORMAL WORLD] Context created.\n" );

	startInput = get_pc();
	printf("Enter 'q' to abort or any other key to continue charging: \n");
	counter = 0;
	printf("CHARGING...\n");
	do 
	{
		startFor = get_pc();
		counter++;
		printf("[");
		for (j=0;j<counter;j++)
			printf("=");
		for (k=j;k<20;k++)
			printf(".");
		printf("]");
		z = (100/20*counter);
		printf("%3d%%", z);
		if(z == 100)
		{
			printf(" [COMPLETED]\n");
			break;
		}
		printf("\r");
		fflush(stdout);
		j++;
		endFor = get_pc();

		startMeasure = get_pc();
	    differenceInBytes = (endFor - startFor) / sizeof(long long int) + sizeof(counter); //plus einmal für das i 

	    //allocate shared memmory
		in_shm.size = differenceInBytes;
		res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
		if (res != TEEC_SUCCESS)
			printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);
		in_shm.buffer = calloc(differenceInBytes-sizeof(counter), sizeof(long long int));
		//fill in the SHḾ
		for (int i = 0; i < differenceInBytes-sizeof(counter); i++)
		{
			memcpy(((long long int *)in_shm.buffer)+i, startFor+i*sizeof(long long int), sizeof(long long int));
		}
		memcpy(((long long int *)in_shm.buffer)+(differenceInBytes-sizeof(counter)), &counter, sizeof(counter));

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);
		//setting params
		op.params[0].memref.parent = &in_shm;
		op.params[0].memref.size = differenceInBytes;
		op.params[0].memref.offset = 0;
		op.params[1].value.a = differenceInBytes;
		op.params[2].value.a = 0;

		res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);

		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);

		TEEC_ReleaseSharedMemory(&in_shm);

		//Measure Function
		endMeasure = get_pc();
		differenceInBytes = (endMeasure - startMeasure) / sizeof(long long int);

		in_shm.size = differenceInBytes;
		res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
		if (res != TEEC_SUCCESS)
			printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);
		in_shm.buffer = calloc(differenceInBytes, sizeof(long long int));
		for (int i = 0; i < differenceInBytes; i++)
		{
			memcpy(((long long int *)in_shm.buffer)+i, startFor+i*sizeof(long long int), sizeof(long long int));
		}


		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);

		//setting params
		op.params[0].memref.parent = &in_shm;
		op.params[0].memref.size = differenceInBytes;
		op.params[0].memref.offset = 0;
		op.params[1].value.a = differenceInBytes;
		op.params[2].value.a = 1;

	
		res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);
		
	
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
		TEEC_ReleaseSharedMemory(&in_shm);

		character=getch();
		if (character == 'q')
			break;				
	}
	while (counter <= 20);

	printf("You have %i kWh in your electricity storage!\n", counter);
	printf("Please confirm the offer of %i kWh: ", counter);
    scanf("%i",&amountT);
    printf("Please type in Szabo/kWh: ");
    scanf("%i",&priceT);
    printf("You sell %i kWh for %i Szabo (%i Szabo/kWh).\n", amountT, priceT*amountT, priceT);
	endInput = get_pc();
	differenceInBytes = (endInput - startInput) / sizeof(long long int); //plus einmal für das i 
	in_shm.size = differenceInBytes;

	res = TEEC_AllocateSharedMemory(&ctx, &in_shm);
	if (res != TEEC_SUCCESS)
		printf("[NORMAL WORLD] Allocation error with code 0x%x\n", res);
	in_shm.buffer = calloc(differenceInBytes, sizeof(long long int));

	//fill in the SHḾ
	for (int i = 0; i < differenceInBytes; i++)
	{
		memcpy(((long long int *)in_shm.buffer)+i, startInput+i*sizeof(long long int), sizeof(long long int));
	}

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_PARTIAL_INPUT, TEEC_VALUE_INOUT, TEEC_VALUE_INOUT, TEEC_NONE);

	//setting params
	op.params[0].memref.parent = &in_shm;
	op.params[0].memref.size = differenceInBytes;
	op.params[0].memref.offset = 0;
	op.params[1].value.a = differenceInBytes;
	op.params[2].value.a = 2;

	res = TEEC_InvokeCommand(&sess, TA_HELLO_WORLD_CHECK_MEMORY_REGION, &op, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", res, err_origin);
	
	TEEC_ReleaseSharedMemory(&in_shm);

	producer(topic, topic_len, priceT, amountT, data, data_len);

	stop_ta_context();
	return 0;
}

TEEC_Result start_ta_context()
{
	TEEC_Result res;
	TEEC_UUID uuid = TA_ECIOTIFY_UUID;

	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) 
	{
		printf("[NORMAL WORLD] Starting TA context failed.\n" );
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);
	}

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
	{
		printf("[NORMAL WORLD] Starting TA session failed.\n" );
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	}

	return TEEC_SUCCESS;
}

void stop_ta_context()
{
	printf("[NORMAL WORLD] Close session.\n");
	TEEC_CloseSession(&sess);

	printf("[NORMAL WORLD] Finalize Context.\n");
	TEEC_FinalizeContext(&ctx);

}

int getch(void) {
      int c=0;

      struct termios org_opts, new_opts;
      int res=0;
          //-----  store old settings -----------
      res=tcgetattr(STDIN_FILENO, &org_opts);
      assert(res==0);
          //---- set new terminal parms --------
      memcpy(&new_opts, &org_opts, sizeof(new_opts));
      new_opts.c_lflag &= ~(ICANON | ECHO | ECHOE | ECHOK | ECHONL | ECHOPRT | ECHOKE | ICRNL);
      tcsetattr(STDIN_FILENO, TCSANOW, &new_opts);
      c=getchar();
          //------  restore old settings ---------
      res=tcsetattr(STDIN_FILENO, TCSANOW, &org_opts);
      assert(res==0);
      return(c);
}
