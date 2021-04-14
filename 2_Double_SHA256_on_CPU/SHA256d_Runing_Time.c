/*********************************************************************
* Filename:   sha256.c
* Author:     HoaiLuan
* Reference: Brad Conte (brad AT bradconte.com)
*********************************************************************/

///*************************** HEADER FILES ***************************/

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>
#include <time.h>
#include "sha256.h"
#include "sha256_stage1.c"
#include "sha256_stage2.c"
#include "sha256_stage3.c"

//#define FILE_OUTPUT "result.txt"

#define NUM_THREADS 16
struct thread_data
{
  int  i;
  int j;
};


uint32_t LitToBigEndian(uint32_t x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}

void *myThreadFun(void *threadid) 
{ 
	clock_t start, end;
	double cpu_time_used;
	start = clock();
    // Store the value argument passed to this thread 
    struct thread_data *data = threadid;

	//printf("Myid = %d \n", data->i );
	
	WORD buf1[8];
	WORD buf2[8];
	WORD buf3[8];
	SHA256_CTX ctx1;
	SHA256_CTX ctx2;
	SHA256_CTX ctx3;
	uint32_t i,j;
	char Version[] = "20c00000";
	char Prev_Hash[] = "00000000000000071817e9b8a491790be5835daf63933485d41752513047a94e";
	char Merk_Hash[] = "bf609e249dd579d2fcc20fc4c15686964bc49fa359d056c595984cf758b2b96d";
	char Time[] = "5F760D01";
	char Target[] = "190c1d72";
	char Nonce[] = "00000000";
	
	////////////Change to Little Endian///////////
	
	//Version
	uint32_t Version_HEX = (uint32_t)strtol(Version, NULL, 16);
	uint32_t Version_LitEndian = LitToBigEndian(Version_HEX);
	
	//Previous hash
	
	uint32_t  Prev_Hash_Int[8];
	char Prev_Hash_temp[8];
	uint32_t  Prev_Hash_Counter = 0;
	uint32_t  Prev_Hash_LitEndian[8];
	
	for (i=0;i<8;i++){
		for(j=i*8;j<i*8+8;j++){
			Prev_Hash_temp[Prev_Hash_Counter] = Prev_Hash[j];
			Prev_Hash_Counter++;
		}
		Prev_Hash_Counter=0;
		Prev_Hash_Int[i] = (uint32_t)strtol(Prev_Hash_temp, NULL, 16);
		Prev_Hash_LitEndian[7-i] = LitToBigEndian(Prev_Hash_Int[i]);
	}
	
	//Merkle hash
	
	uint32_t  Merk_Hash_Int[8];
	char Merk_Hash_temp[8];
	uint32_t  Merk_Hash_Counter = 0;
	uint32_t  Merk_Hash_LitEndian[8];
	
	for (i=0;i<8;i++){
		for(j=i*8;j<i*8+8;j++){
			Merk_Hash_temp[Merk_Hash_Counter] = Merk_Hash[j];
			Merk_Hash_Counter++;
		}
		Merk_Hash_Counter=0;
		Merk_Hash_Int[i] = (uint32_t)strtol(Merk_Hash_temp, NULL, 16);
		Merk_Hash_LitEndian[7-i] = LitToBigEndian(Merk_Hash_Int[i]);
	}

	//Timestamp
	uint32_t Time_HEX = (uint32_t)strtol(Time, NULL, 16);
	uint32_t Time_LitEndian = LitToBigEndian(Time_HEX);
	
	//Target
	uint32_t Target_HEX = (uint32_t)strtol(Target, NULL, 16);
	uint32_t Target_LitEndian = LitToBigEndian(Target_HEX);
	//Nonce
	uint32_t Nonce_HEX = (uint32_t)strtol(Nonce, NULL, 16);
	uint32_t Nonce_LitEndian = LitToBigEndian(Nonce_HEX);
	
	WORD Word1[16] = {Version_LitEndian, Prev_Hash_LitEndian[0], Prev_Hash_LitEndian[1], Prev_Hash_LitEndian[2], Prev_Hash_LitEndian[3], Prev_Hash_LitEndian[4], Prev_Hash_LitEndian[5], Prev_Hash_LitEndian[6], Prev_Hash_LitEndian[7], Merk_Hash_LitEndian[0], Merk_Hash_LitEndian[1], Merk_Hash_LitEndian[2], Merk_Hash_LitEndian[3], Merk_Hash_LitEndian[4], Merk_Hash_LitEndian[5], Merk_Hash_LitEndian[6]};
	
	


	
	sha256_init_1(&ctx1);
	sha256_update_1(&ctx1, Word1, buf1);
	uint32_t nonce = 0;
	for(nonce = data->i*268435456; nonce < (data->i + 1)*268435456; nonce++){
		WORD Word2[16] = {Merk_Hash_LitEndian[7], Time_LitEndian, Target_LitEndian, nonce, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000280};	
		sha256_init_2(&ctx2,buf1);
		sha256_update_1(&ctx2, Word2, buf2);
		
		sha256_init_3(&ctx3);
		sha256_update_3(&ctx3, buf2, buf3);
	}
	//printf("Nonce %d: %08x%08x%08x%08x%08x%08x%08x%08x", nonce,buf3[0],buf3[1],buf3[2],buf3[3],buf3[4],buf3[5],buf3[6],buf3[7]);
	//printf("\n\r");
  
	end = clock();
	 
	//cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	//printf("Thread %d: %f second \n",cpu_time_used);
    // Print the argument, static and global variables 
    //printf("Thread ID: %d, Static: %d, Global: %d\n", *myid, ++s, ++g); 
} 



uint32_t main(void)
{
	pthread_t threads[NUM_THREADS];
	
	clock_t start, end;
	double cpu_time_used;
	start = clock();
	int rc;
	uint32_t i;
		for (i=0; i <NUM_THREADS; i++){	
			struct thread_data *data = (struct thread_data *) malloc(sizeof(struct thread_data));
			data->i = i;
			//data->j = j;
			pthread_create(&threads[i], NULL, myThreadFun,data); 

      }
	

	pthread_exit(NULL);
	end = clock();
	 
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;
	printf("time used: %f second \n",cpu_time_used);
	return 0;
}