// cd /home/hork/cuda-workspace/CudaSHA256/Debug/files
// time ~/Dropbox/FIIT/APS/Projekt/CpuSHA256/a.out -f ../file-list
// time ../CudaSHA256 -f ../file-list


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cuda.h>
#include "sha256.cuh"
#include <dirent.h>
#include <ctype.h>
#include <sys/time.h>

#define FILE_OUTPUT "timing_report.log"

#define N 65536
#define BLOCKSIZE 196
#define M 4294967296/N

void string2ByteArray(char* input, BYTE* output)
{
    uint32_t loop;
    uint32_t i;
    
    loop = 0;
    i = 0;
    
    while(input[loop] != '\0')
    {
        output[i++] = input[loop++];
    }
}

uint32_t LitToBigEndian(uint32_t x)
{
	return (((x>>24) & 0x000000ff) | ((x>>8) & 0x0000ff00) | ((x<<8) & 0x00ff0000) | ((x<<24) & 0xff000000));
}

__global__ void sha256_cuda(JOB ** jobs, uint32_t n, uint32_t j, OUT * outs) {

   uint32_t index = blockIdx.x * blockDim.x + threadIdx.x;
  uint32_t stride = blockDim.x * gridDim.x;
 
  for (uint32_t i = index; i < n; i += stride){
		SHA256_CTX ctx;
		//sha256_init_23(&ctx);
		WORD temp1[8];
		WORD temp2[8];
		jobs[i]->data2[3] = j*n+i;
		sha256_transform_2(&ctx, jobs[i]->data1, temp1);
		sha256_transform_1(&ctx, temp1, jobs[i]->data2, temp2);
		
		uint32_t k;
		for (k = 0; k < 8; k++)
		{
		jobs[i]->temp[k] = temp2[k];
		}
		jobs[i]->temp[8] = 0x80000000;
		for (k = 9; k < 14; k++)
		{
		jobs[i]->temp[k] = 0;
		}
		jobs[i]->temp[15] = 0x00000100;

		sha256_transform_2(&ctx, jobs[i]->temp, jobs[i]->digest);
		
		uint32_t m;
		
		uint32_t Final_Hash[8];
		
		for (m = 0; m < 8; m++)
		{
			Final_Hash[7-m] =  ((jobs[i]->digest[m]>>24) & 0x000000ff) | ((jobs[i]->digest[m]>>8) & 0x0000ff00) | ((jobs[i]->digest[m]<<8) & 0x00ff0000) | ((jobs[i]->digest[m]<<24) & 0xff000000);
		}
		
		int valid = 1;
		for ( m = 0; m < outs->NUM; m ++){
			if(Final_Hash[m] > outs->TARGET[m])
				valid = 0;
		}
		
		if(valid){
			outs->NONCE = jobs[i]->data2[3];
			for (m = 0; m < 8; m++)
			{
				outs->VALID_H[m] =  Final_Hash[m];
			}
		}
	}
}

void pre_sha256() {
	// compy symbols
	checkCudaErrors(cudaMemcpyToSymbol(dev_k, host_k, sizeof(host_k), 0, cudaMemcpyHostToDevice));
}

void runJobs(JOB ** jobs, uint32_t n, uint32_t j, OUT * outs){
	
	uint32_t blockSize = BLOCKSIZE;
	uint32_t numBlocks = (n + blockSize - 1) / blockSize;
	sha256_cuda <<< numBlocks, blockSize >>> (jobs, n, j,outs);
	//sha256_cuda <<< 1, 1 >>> (jobs, n, j, outs);
	//sha256_cuda <<< 1, 16 >>> (jobs, n);
}

JOB * JOB_init(const WORD data1[], const WORD data2[], const WORD H[]) {
	JOB * j;
	checkCudaErrors(cudaMallocManaged(&j, sizeof(JOB)));

	for (uint32_t i = 0; i < 16; i++)
	{
		j->data1[i] = data1[i];
	}
	
	for (uint32_t i = 0; i < 16; i++)
	{
		j->data2[i] = data2[i];
	}

	for (uint32_t i = 0; i < 8; i++)
	{
		j->H[i] = H[i];
	}
		
	return j;
}

int main(void)
{
	JOB ** jobs;
	OUT * outs;
	WORD buf1[8];
	uint32_t i,j;

	FILE* fo = fopen(FILE_OUTPUT, "w+");

	////////////////////////////////
	//**BitcoinAtom Block Header**//
	///////////////////////////////

	/*char Version[] = "2000e000";
	char Prev_Hash[] = "000000000000000f5edd17eb45ea50489d171d13e5255fe1ee9e49084eeb65ab";
	char Merk_Hash[] = "f896a21b7213eb5f1b8ba73b277fba850f6ad4eaf9cfa72a2a1b0986e04cdcd5";
	char Time[] = "5F718F4E";
	char Target[] = "1928d33c";*/
	
	////////////////////////////////
	//**BitcoinCash Block Header**//
	///////////////////////////////

	/*char Version[] = "20e00000";
	char Prev_Hash[] = "00000000000000000150983ec2829d878c4b3c65dbb3b2b91bb68e2d5073314d";
	char Merk_Hash[] = "11f642ffaf5fd182bea3c41ce8a635b2b92aa03a7c362171b777a63c5e540f89";
	char Time[] = "5F6F4F19";
	char Target[] = "1802f9c7";*/
	
	////////////////////////////////
	//** BitcoinV Block Header  **//
	///////////////////////////////

	/*char Version[] = "20c00000";
	char Prev_Hash[] = "00000000000000071817e9b8a491790be5835daf63933485d41752513047a94e";
	char Merk_Hash[] = "bf609e249dd579d2fcc20fc4c15686964bc49fa359d056c595984cf758b2b96d";
	char Time[] = "5F760D01";
	char Target[] = "190c1d72";*/
	
	////////////////////////////////
	//**EmbargoCoin Block Header**//
	///////////////////////////////

	/*char Version[] = "00000002";
	char Prev_Hash[] = "0000061e5616fa75619116059b18facaf5e31f661aab1c3548dd3cb061cc9b05";
	char Merk_Hash[] = "46d2deb2ca2340bd17ef5166e24c0475ab1950fc5ef5a90defbe40467ad8afce";
	char Time[] = "5F6F4951";
	char Target[] = "1e0962d9";*/

	////////////////////////////////
	//**EmbargoCoin Block Header**//
	///////////////////////////////
	
	/*char Version[] = "00000002";
	char Prev_Hash[] = "0000061e5616fa75619116059b18facaf5e31f661aab1c3548dd3cb061cc9b05";
	char Merk_Hash[] = "46d2deb2ca2340bd17ef5166e24c0475ab1950fc5ef5a90defbe40467ad8afce";
	char Time[] = "5F6F4951";
	char Target[] = "1e0962d9";*/

	////////////////////////////////
	//** FreiCoin Block Header  **//
	///////////////////////////////
	
	/*char Version[] = "20800000";
	char Prev_Hash[] = "0000000000000116a9ff19c489f2bdba49c387d7da193015ab3aa6a222150573";
	char Merk_Hash[] = "8516eb1f8561b4c954f32bd3f59cae603ba773c6925523b29fad20df9ec84a6d";
	char Time[] = "5F6F474B";
	char Target[] = "1a01e394";*/

	////////////////////////////////
	//** JouleCoin Block Header  **//
	///////////////////////////////
	
	/*char Version[] = "00400004";
	char Prev_Hash[] = "000000000000525e9ed757b108c9c593fb35108fb35f03fd087cfbbc2e71cddb";
	char Merk_Hash[] = "641a7ffbd1a0479428f1d3f803880a86cc7ed914ec97932d780eb7ef9c69ca1b";
	char Time[] = "5F6A3C6F";
	char Target[] = "1b00931b";*/

	////////////////////////////////
	//**Kryptofranc Block Header**//
	///////////////////////////////
	
	/*char Version[] = "20000000";
	char Prev_Hash[] = "0000000000000196d80d750006472b0786fa607114574330a28bc7afe7ef8e70";
	char Merk_Hash[] = "914cfe3a7005c76f808781fafeab874300c514a1a886160e429283906104a3ed";
	char Time[] = "5F71CD79";
	char Target[] = "1a028a1e";*/

	////////////////////////////////
	//** ZetaCoin Block Header **//
	///////////////////////////////
	
	/*char Version[] = "00000002";
	char Prev_Hash[] = "00000000000eb602457fec75d26912c30b8f6740ee26bd53b7a1235dd7847c78";
	char Merk_Hash[] = "3d4874f4a1449e13b303dcd0b74eddd47c1f9b5b8edd2d9d0069163ac56f2fbe";
	char Time[] = "52166E7B";
	char Target[] = "1b176520";*/

	////////////////////////////////
	//**  Bitcoin Block Header  **//
	///////////////////////////////
	
	char Version[] = "37FFE000";
	char Prev_Hash[] = "000000000000000000038973ac554e90636fae2995efa0d1725c00ac4e7dbc35";
	char Merk_Hash[] = "1ef117d88223949d22091e9f6aa01e7f614b9c7e7a609c25808b413639151683";
	char Time[] = "5F715CF2";
	char Target[] = "170E92AA";

	////////////Change to Little Endian///////////
	fprintf(fo, "----------------------We are trying to mine a Bitcoin block----------------------\n");
	fprintf(fo, "*Block header information:\n");
	fprintf(fo, "	+Version : %s\n", Version);
	fprintf(fo, "	+Previous Hash : %s\n", Prev_Hash);
	fprintf(fo, "	+Merkle Hash : %s\n", Merk_Hash);
	fprintf(fo, "	+Timestemp : %s\n", Time);
	fprintf(fo, "	+Target : %s\n", Target);

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
	
	uint32_t nbit1 = (Target_HEX >> 24)&0x000000ff;
	uint32_t nbit2 = (Target_HEX >> 16)&0x000000ff;
	uint32_t nbit3 = (Target_HEX >> 8)&0x000000ff;
	uint32_t nbit4 = (Target_HEX)&0x000000ff;

	uint32_t target_8b[32];
	for( i = 0; i < 32; i++){
		if(i == (32 - nbit1 + 2)) {
			target_8b[i] = nbit4;
		}
		else if(i == (32 - nbit1 + 1)) {
			target_8b[i] = nbit3;
		}
		else if(i == (32 - nbit1)) {
			target_8b[i] = nbit2;
		}
		else {
			target_8b[i] = 0;
		}
	}
	
	uint32_t Target_32b[8];
	
	for( i = 0; i < 8; i++){
		Target_32b[i] = (target_8b[i*4]<<24)|(target_8b[i*4 + 1] << 16)|(target_8b[i*4 + 2] << 8)|(target_8b[i*4 + 3]);
	}
	
	int num_int = (32 - nbit1+3) / 4;
	
	checkCudaErrors(cudaMallocManaged(&outs, sizeof(OUT)));
	outs->NUM = num_int;

	
	for( i = 0; i < 8; i++){
		outs->TARGET[i] = Target_32b[i];
	}

	
	fprintf(fo, "*Start to mine........\n");
	clock_t start, end;
	double cpu_time_used;
	int GPU_N;
	start = clock();
	checkCudaErrors(cudaGetDeviceCount(&GPU_N));
	checkCudaErrors(cudaSetDevice(GPU_N-2));
	//sha256_transform_0(&ctx1, Word1, buf1);
	
	checkCudaErrors(cudaMallocManaged(&jobs, N * sizeof(JOB *)));

	for (i=0; i < N; ++i){	
			WORD Word1[16] = {Version_LitEndian, Prev_Hash_LitEndian[0], Prev_Hash_LitEndian[1], Prev_Hash_LitEndian[2], Prev_Hash_LitEndian[3], Prev_Hash_LitEndian[4], Prev_Hash_LitEndian[5], Prev_Hash_LitEndian[6], Prev_Hash_LitEndian[7], Merk_Hash_LitEndian[0], Merk_Hash_LitEndian[1], Merk_Hash_LitEndian[2], Merk_Hash_LitEndian[3], Merk_Hash_LitEndian[4], Merk_Hash_LitEndian[5], Merk_Hash_LitEndian[6]};
			WORD Word2[16] = {Merk_Hash_LitEndian[7], Time_LitEndian, Target_LitEndian, 0x00000000, 0x80000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000280};	
			jobs[i] 	   = JOB_init(Word1, Word2, buf1);
	}

	for(j = 0; j <M; ++j){
		pre_sha256();
		runJobs(jobs, N, j, outs);
	}
	cudaDeviceSynchronize();	

	end = clock();
	cpu_time_used = ((double) (end - start)) / CLOCKS_PER_SEC;

	fprintf(fo, "*Execution Time of 2^32 hashes on GPU : %f seconds\n", cpu_time_used);

	fprintf(fo, "*A found nonce:%08x\n", outs->NONCE);

	fprintf(fo, "*A valid hash: ");

	for (i = 0; i < 8; i++)
		{
			fprintf(fo, "%08x",outs->VALID_H[i]);
		}
	fprintf(fo, "\n");
	cudaDeviceReset();


	return 0;
}	
	
