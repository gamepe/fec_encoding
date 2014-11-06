// fec.cpp : Defines the entry point for the console application.
//



#define _CRTDBG_MAP_ALLOC


#include <io.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <tchar.h>
#include <stdlib.h>
#include <crtdbg.h>
#include "stdafx.h"
#include <string.h>
#ifndef PLATFORM_LINUX
#else
#include <stdlib.h>
#endif
#include "fec.h"
#include "io.h"
#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* malloc, free, rand */
#include<Windows.h>
#include "crc.h"x	
#include <time.h>
#include<winsock.h>
#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#define PHP_FILE_PATH         "file.php"
#define ENCODED_OUTPUT_PATH   "encoded_output.hex"
#define DECODED_OUTPUT_PATH   "decoded.bin"
#define DEFRAG_FILE_PATH      "defrag.hex"

char g_szDirectoryToTar[MAX_PATH];
char g_szFileToBZ2[MAX_PATH];

#define SSID_FILE_BIN "ssid.bin"
#define SSID_FILE_SCRIPT "ssid.php"


//chunk of 132 BYTES will be send as 1 SMS UDH=0
#define CHUNKS_SIZE 126-sizeof(XCHUNK_HDR)  //must be dived by 4

uint8_t parity_bytes[MAXIMUM_IMPLEMENTED_PARITY_BYTES];

#define TYPE_SSID   33
#define TYPE_CHUNK  32
#define TYPE_REBOOT 34

#pragma pack(1)

struct XCOMMAND_HDR
{


	unsigned short  magic;
	unsigned char   fec_hdr[8];                //on the chunk data
	unsigned short  type;
	unsigned short  length;
	

};
struct XCHUNK_HDR
{

	unsigned short  magic;
	unsigned char   fec_hdr[8];                //on the chunk data
	unsigned short  type;
	unsigned short  indx;  //  index + 32 indx of chunk
	unsigned short  total_indx;
	unsigned short  size;  //  size +32      //sizeof chunk

};
struct XSSID_HDR
{


	unsigned short  magic;
	unsigned char   fec_hdr[8];                //on the chunk data
	unsigned short  type;
	unsigned short  length;  //  size +32      //sizeof chunk

};
#pragma pack()


unsigned char * encode_reboot(unsigned char *pbuffer=0, unsigned short size=0)
{


	unsigned short length = size;

	unsigned char *buffer = (unsigned char*)malloc(length + sizeof(XCOMMAND_HDR));

	XCOMMAND_HDR *cmd_hdr = (XCOMMAND_HDR*)buffer;
	cmd_hdr->magic = 0;
	//memcpy(ssid_hdr->fec_hdr, get_parity_bytes(ssid, length), 8);
	memset(cmd_hdr->fec_hdr, 0xCC, 8);
	cmd_hdr->length = htons(length);
	cmd_hdr->type = htons(TYPE_REBOOT);
	if (pbuffer){
		memcpy(buffer + sizeof(XCOMMAND_HDR), pbuffer, length);

	}

	return buffer;


}
unsigned char  genrate_random_byte()
{

	unsigned char number = 0;
	do{
		srand(time(0)); //i.e. value = time(NULL) from time.h/ctime.h
		number = rand() % 256;

	} while ((!(number >> 4)) && number != 0xD0);

	number = number ^ 0xD0;

	if (!number) genrate_random_byte();

	return number;
}




unsigned char * get_parity_bytes(unsigned char *msg, unsigned short length)
{


	fec_init(8);

	fec_encode((uint8_t *)msg, length, parity_bytes);


	return parity_bytes;


}





/*

Yes. The maximum length of text message that you can send is 918 characters.
However, if you send more than 160 characters then your message will be broken
down in to chunks of 153 characters before being sent to the recipient's handset.
153*6= 918


*/

unsigned char * encode_ssid(unsigned char *ssid, unsigned short *size)
{


	unsigned short length = strlen((char*)ssid);

	unsigned char *buffer = (unsigned char*)malloc(length + sizeof(XSSID_HDR));

	if (!buffer) return 0;

	XSSID_HDR *ssid_hdr = (XSSID_HDR*)buffer;
	ssid_hdr->magic = 0;
	//memcpy(ssid_hdr->fec_hdr, get_parity_bytes(ssid, length), 8);
	memset(ssid_hdr->fec_hdr, 0xCC, 8);
	ssid_hdr->length = htons(length);
	ssid_hdr->type = htons(TYPE_SSID);
	memcpy(buffer + sizeof(XSSID_HDR), ssid, length);

	*size = length + sizeof(XSSID_HDR);




	return buffer;


}


unsigned short get_fecbytescount_inchunk(unsigned char * pdata, unsigned short chunkSize)
{

	//D800–DFFF


	unsigned short correct_bytes_indx = 0;
	for (unsigned short i = 0; i < chunkSize;)
	{

		unsigned short ch = htons(*(unsigned short *)&pdata[i]);

		if (ch >= 0xD800 && ch <= 0xDFFF) {
			//printf("found  surrogate pair @ index =%d %04X \n", i, ch);
			correct_bytes_indx++;
		}

		i += 2;
	}

	return correct_bytes_indx;
}

unsigned short  patch_fecbytes_inchunk(unsigned char * pdata, unsigned short chunkSize)
{

	unsigned short correct_bytes_indx = 0;
	int size = chunkSize;
	if (size % 2 != 0){

		size -= 1;
	}

	for (unsigned short i = 0; i < size;)
	{
		unsigned short ch = htons(*(unsigned short *)&pdata[i]);

		if (ch >= 0xD800 && ch <= 0xDFFF) {
			correct_bytes_indx++;

			unsigned short patch = 0xCC00;
			patch |= ch & 0xFF;

			*(unsigned short *)&pdata[i] = htons(patch);
		}

		i += 2;
	}

	return correct_bytes_indx;
}


unsigned char * get_splitchunk_by_indx(unsigned char * pdata, unsigned short chunksSize, unsigned  short total_split, int index)
{

	unsigned  short chunkSizeSplit = 4;

	unsigned char *p = pdata + chunkSizeSplit*index;

	return p;

}

unsigned  short  split_chunk(unsigned char * pdata, unsigned short chunksSize)
{

	unsigned  short total_split = 0;

	while (chunksSize) {

		total_split++;
		chunksSize -= 4;

	}

	return total_split;

}





unsigned short  calc_total_fec_chunks(char *input_file, unsigned short ChunkSize = 140)
{

	unsigned char * file_contents = 0;
	unsigned int file_length = -1;

	unsigned short outfile_size = -1;

	file_contents = read_whole_file(input_file, &file_length);
	if (file_length < ChunkSize){

		printf("calc_total_fec_chunks :Error  file input size smaller than chunk size [%d vs %d]\n", file_length, ChunkSize);
		free(file_contents);
		return -1;
	}

	if (file_contents != 0){


		int correct_bytes_indx = 0;

		unsigned short chunksSize = ChunkSize;
		unsigned short remainChunkSize = 0;
		unsigned short nChunks = 0;

		unsigned short nTotalChunks = 0;
		if (file_length > chunksSize) {

			nChunks = file_length / chunksSize;
			remainChunkSize = file_length - nChunks*chunksSize;
			nTotalChunks = nChunks;
			if (remainChunkSize != 0)
				nTotalChunks++;

		}
		else {
			chunksSize = file_length;
			remainChunkSize = 0;
			nChunks = 1;
			nTotalChunks = 1;
			free(file_contents);
			return nTotalChunks;
		}

		printf("calc_total_fec_chunks:Chunk size=%d remain chunk=%d total %d chunks\n", chunksSize, remainChunkSize, nTotalChunks);
		printf("calc_total_fec_chunks:file length=%d =%d\n", file_length, chunksSize*nChunks + remainChunkSize);


		unsigned char *buffer = 0;
		unsigned char *cp = file_contents;

		unsigned short  chunk_index = 1;
		for (int j = 0; j < (file_length - remainChunkSize); j += chunksSize){

			chunk_index++;


			buffer = (unsigned char*)malloc(chunksSize);
			unsigned char *pdata = buffer;
			memcpy(pdata, cp, chunksSize);


			//hexDump("chunk", pdata, ChunkSize);
			correct_bytes_indx = get_fecbytescount_inchunk(pdata, chunksSize);


			if (correct_bytes_indx > 4){


				//printf("*calc_total_fec_chunks:start spliting chunk size %d and fec %d bytes fec wait...\n", chunksSize, correct_bytes_indx);
				unsigned short split_count = split_chunk(pdata, chunksSize);

				//printf("split_count=%d,\n", split_count);
				if (split_count != (unsigned short)-1) {


					nTotalChunks = nTotalChunks + split_count - 1;
				}
				else
					nTotalChunks = -1;


			}

			free(buffer);
			cp += chunksSize;



		}

		if (remainChunkSize != 0) {


			buffer = (unsigned char*)malloc(chunksSize);
			memset(buffer, 0xCC, chunksSize);
			unsigned char *pdata = buffer;
			memcpy(pdata, cp, remainChunkSize);
			//hexDump("chunk", pdata, remainChunkSize);
			correct_bytes_indx = get_fecbytescount_inchunk(pdata, chunksSize);


			if (correct_bytes_indx > 4){

				//printf("**calc_total_fec_chunks:start spliting %d bytes fec wait...\n", correct_bytes_indx);
				unsigned short split_count = split_chunk(pdata, chunksSize);
				//printf("split_count=%d,\n", split_count);
				if (split_count != (unsigned short)-1)
					nTotalChunks = nTotalChunks + split_count - 1;
				else
					nTotalChunks = -1;

			}

			free(buffer);
		}



		free(file_contents);
		printf("calc_total_fec_chunks:Chunk size=%d remain chunk=%d total %d chunks\n", chunksSize, remainChunkSize, nTotalChunks);
		printf("calc_total_fec_chunks:file length=%d =%d\n", file_length, chunksSize*nChunks + remainChunkSize);

		return nTotalChunks;
	}

	return -1;



}


unsigned char* encode_chunk(unsigned char * pdata, unsigned short chunksSize, unsigned char reference_number, unsigned short type,
	unsigned short  indx, unsigned short  total_indx)
{



	unsigned char* buffer = (unsigned char*)malloc(chunksSize + sizeof(XCHUNK_HDR));

	XCHUNK_HDR xchunk_hdr = { 0 };
	memcpy(xchunk_hdr.fec_hdr, get_parity_bytes(pdata, chunksSize), sizeof(xchunk_hdr.fec_hdr));
	xchunk_hdr.magic = reference_number;
	xchunk_hdr.type = htons(type);
	xchunk_hdr.size = htons(chunksSize);
	xchunk_hdr.indx = htons(indx);
	xchunk_hdr.total_indx = htons(total_indx);

	hexDump("fec_hdr", xchunk_hdr.fec_hdr, sizeof(XCHUNK_HDR));
	for (int i = 0; i < sizeof(xchunk_hdr.fec_hdr); i += 2) {



		if (xchunk_hdr.fec_hdr[i] >= (unsigned char)0xD8 && xchunk_hdr.fec_hdr[i] <= (unsigned char)0xDF){


			xchunk_hdr.fec_hdr[i] ^= 0xD0;

			switch (i) {
			case 0:
				xchunk_hdr.magic |= 0x0100; break;
			case 2:
				xchunk_hdr.magic |= 0x0200; break;
			case 4:
				xchunk_hdr.magic |= 0x0400; break;
			case 6:
				xchunk_hdr.magic |= 0x0800; break;
			default: ///never reach here 
				xchunk_hdr.magic = 0x00CC; break;

			}

		}

	}

	memcpy(buffer, &xchunk_hdr, sizeof(XCHUNK_HDR));
	

	memcpy(buffer + sizeof(XCHUNK_HDR), pdata, chunksSize);

//hexDump("encode",buffer, sizeof(XCHUNK_HDR)+chunksSize);
	//Sleep(5000);

	patch_fecbytes_inchunk(buffer + sizeof(XCHUNK_HDR), chunksSize);

	return buffer;
}



int save2file(char *outputfile, unsigned char * pdata, unsigned short chunksSize)
{
	FILE *outfile = fopen(outputfile, "ab");

	if (outfile != NULL){
		fseek(outfile, 0, SEEK_END);
		fwrite(pdata, sizeof(unsigned  char), chunksSize, outfile);
		fclose(outfile);
		return 1;
	}
	return 0;

}


int encode_file(char *input_file, char *outputfile, unsigned short ChunkSize = 140)
{




	printf("[*]encode_File outputfile  %s\n", outputfile);
	unsigned char * file_contents = 0;
	unsigned int file_length = -1;
	unsigned short  reference_number = -1, type = -1;

	unsigned int outfile_size = 0;
	unsigned short total_chunks = 0, chunk_index = 0;
	total_chunks = calc_total_fec_chunks(input_file, ChunkSize);

	file_contents = read_whole_file(input_file, &file_length);
	if (!file_contents && file_length < ChunkSize){

		printf("EncodeBZ2File :Error  file input size smaller than chunk size [%d vs %d]\n", file_length, ChunkSize);

		free(file_contents);

		return 0;
	}

	if (file_contents != 0){

		printf("encode_File:start encoding please wait...\n");

		reference_number = genrate_random_byte();
		type = TYPE_CHUNK;

		unsigned short chunksSize = ChunkSize;
		unsigned short remainChunkSize = 0;
		unsigned short nChunks = 0, nTotalChunks = 0;

		if (file_length > chunksSize) {

			nChunks = file_length / chunksSize;
			remainChunkSize = file_length - nChunks*chunksSize;
			nTotalChunks = nChunks;
			if (remainChunkSize != 0)
				nTotalChunks++;

		}
		else {
			chunksSize = file_length;
			remainChunkSize = 0;
			nChunks = 1;
			nTotalChunks = 1;

		}
		unsigned char *buffer = 0;
		unsigned char *cp = file_contents;

		unsigned short  chunk_index = 1;
		for (int j = 0; j < (file_length - remainChunkSize); j += chunksSize){



			buffer = (unsigned char*)malloc(chunksSize);

			unsigned char *pdata = buffer;
			memcpy(pdata, cp, chunksSize);


			unsigned short correct_bytes_indx = get_fecbytescount_inchunk(pdata, chunksSize);

			if (correct_bytes_indx > 4){


				//printf("start spliting %d bytes fec from chunk size=%d please wait...\n", correct_bytes_indx, chunksSize);
				unsigned short split_count = split_chunk(pdata, chunksSize);

				//printf("split_count=%d,\n", split_count);
				if (split_count == (unsigned short)-1 || split_count == 0) {

					printf("[*]encode_File:split_chunk:error\n");

					free(buffer);
					free(file_contents);

					return 0;

				}




				for (int i = 0; i < split_count; i++){

					unsigned  short chunkSizeSplit = chunksSize / split_count;


					unsigned char *psplit_data = get_splitchunk_by_indx(pdata, chunksSize, split_count, i);

					unsigned short correct_bytes_indx = get_fecbytescount_inchunk(psplit_data, chunkSizeSplit);
					//printf("corrected byte in split chunk=%d\n", correct_bytes_indx);

					//hexDump("chunk", psplit_data, chunkSizeSplit);

					unsigned char * encoded_chunk = encode_chunk(psplit_data, chunkSizeSplit, reference_number, type, chunk_index, total_chunks);
					if (encoded_chunk) {
						save2file(outputfile, encoded_chunk, chunkSizeSplit + sizeof(XCHUNK_HDR));
						outfile_size += chunkSizeSplit + sizeof(XCHUNK_HDR);
						free(encoded_chunk);
						chunk_index++;
					}
					else{

						printf("encode_chunk:CRITICAL EROOR");
						while (1);
					}
				}



			}
			else {

				unsigned char * encoded_chunk = encode_chunk(pdata, chunksSize, reference_number, type, chunk_index, total_chunks);

				if (encoded_chunk){
					chunk_index++;

					save2file(outputfile, encoded_chunk, chunksSize + sizeof(XCHUNK_HDR));

					outfile_size += chunksSize + sizeof(XCHUNK_HDR);
					free(encoded_chunk);
				}
				else{

					printf("encode_chunk:CRITICAL EROOR");
					while (1);
				}
			}


			free(buffer);


			cp += chunksSize;

		}


		if (remainChunkSize != 0){


			buffer = (unsigned char*)malloc(chunksSize);

			memset(buffer, 0x00, chunksSize);

			unsigned char *pdata = buffer;
			memcpy(pdata, cp, remainChunkSize);

			unsigned short correct_bytes_indx = get_fecbytescount_inchunk(pdata, chunksSize);

			if (correct_bytes_indx > 4){


				//printf("!start spliting %d bytes fec from chunk size=%d please wait...\n", correct_bytes_indx, remainChunkSize);
				unsigned short split_count = split_chunk(pdata, chunksSize);

				//printf("split_count=%d,\n", split_count);
				if (split_count == (unsigned short)-1 || split_count == 0) {

					printf("[!]split_chunk:error\n");
					free(buffer);
					free(file_contents);

					return 0;

				}

				for (int i = 0; i < split_count; i++){

					unsigned  short chunkSizeSplit = chunksSize / split_count;
					unsigned char *psplit_data = get_splitchunk_by_indx(pdata, chunksSize, split_count, i);

					unsigned char * encoded_chunk = encode_chunk(psplit_data, chunkSizeSplit, reference_number, type, chunk_index, total_chunks);



					save2file(outputfile, encoded_chunk, chunkSizeSplit + sizeof(XCHUNK_HDR));
					outfile_size += chunkSizeSplit + sizeof(XCHUNK_HDR);


					free(encoded_chunk);
					free(buffer);
					chunk_index++;
				}

			}
			else{


				unsigned char * encoded_chunk = encode_chunk(pdata, remainChunkSize, reference_number, type, chunk_index, total_chunks);

				if (encoded_chunk) {

					XCHUNK_HDR *pchunk_hdr = (XCHUNK_HDR*)encoded_chunk;
					pchunk_hdr->size = htons(remainChunkSize);
					save2file(outputfile, encoded_chunk, remainChunkSize + sizeof(XCHUNK_HDR));
					outfile_size += chunksSize + sizeof(XCHUNK_HDR);
					free(encoded_chunk);
					free(buffer);

				}
				else
				{
					printf("critical error");
					while (1);
				}
			}

		}

		printf("total size of output file =%d bytes\n", outfile_size);
		free(file_contents);

		return TRUE;
	}
	printf("encode: fail to read input file %s\n", input_file);
	return FALSE;
}


void bin_to_strhex(unsigned char *bin, unsigned int binsz, char **result)
{
	char          hex_str[] = "0123456789abcdef";
	unsigned int  i;

	*result = (char *)malloc(binsz * 2 + 1);
	(*result)[binsz * 2] = 0;

	if (!binsz)
		return;

	for (i = 0; i < binsz; i++)
	{
		(*result)[i * 2 + 0] = hex_str[bin[i] >> 4];
		(*result)[i * 2 + 1] = hex_str[bin[i] & 0x0F];
	}
}

void create_php_script(char *input_file, char *output_file = "file.php", char *varname = "sms_file")
{

	unsigned char * file_contents = 0;
	unsigned int file_length = -1;


	file_contents = read_whole_file(input_file, &file_length);

	if (!file_contents) return;

	char *result = 0;



	bin_to_strhex((unsigned char *)file_contents, file_length, &result);


	char *jason_frmt = (char*)malloc(strlen(result) * 6);
	memset(jason_frmt, 0, strlen(result) * 6);

	strcpy(jason_frmt, "<?php \n");

	char buf[0x100];
	sprintf(buf, "$%s=\'[\"", varname);
	strcat(jason_frmt, buf);


	for (int i = 0; i < strlen(result) - 2; i += 4){

		char buf[7] = { '\\', 'u' };
		buf[6] = 0;
		strncpy(&buf[2], result + i, 4);
		strcat(jason_frmt, buf);



	}

	if (strlen(result) % 4 != 0) {

		char buf[7] = { '\\', 'u', 'f', 'f' };
		buf[6] = 0;
		strncpy(&buf[4], &result[strlen(result) - 2], 2);
		strcat(jason_frmt, buf);

	}

	strcat(jason_frmt, "\"]\';");
	strcat(jason_frmt, "\n\n?>");

	FILE *outfile = fopen(output_file, "a");
	printf("flash to file...\n");
	if (outfile != NULL){
		fseek(outfile, 0, SEEK_END);
		fwrite(jason_frmt, sizeof(unsigned  char), strlen(jason_frmt), outfile);
		fclose(outfile);

	}

	free(jason_frmt);
	free(result);
	free(file_contents);

}

int verify_file(char *input_file)
{

	unsigned char * file_contents = 0;
	unsigned int file_length = -1;

	int fOK = 1;
	file_contents = read_whole_file(input_file, &file_length);

	if (!file_contents) return FALSE;


	int size = file_length;
	if (size % 2 != 0){

		size -= 1;
	}

	for (unsigned int i = 0; i < size;)
	{
		unsigned short ch = htons(*(unsigned short *)&file_contents[i]);

		if (ch >= 0xD800 && ch <= 0xDFFF) {

			//printf("FOUND BAD CHAR @ offset %02X\n", i);
			fOK = 0;


		}

		i += 2;
	}

	free(file_contents);

	return fOK;
}




int defrag_file(char *input_file, char *outputfile)
{


	unsigned char * file_contents = 0;
	unsigned int file_length = -1;

	file_contents = read_whole_file(input_file, &file_length);

	if (!file_contents) return 0;
	printf("defrag_file:length =%d\n", file_length);

	XCHUNK_HDR *pchunkhdr = (XCHUNK_HDR*)(unsigned char*)file_contents;

	printf("defrag_file:chunk size =%02X total sms=%d\n", htons(pchunkhdr->size), htons(pchunkhdr->total_indx));

	unsigned short total_chunks = htons(pchunkhdr->total_indx);
	unsigned short chunk_size = htons(pchunkhdr->size);
	unsigned char **ptr = NULL;

	ptr = (unsigned char**)malloc(sizeof(char *)* total_chunks);
	unsigned int total_parsed_length = 0;

	if (ptr){

		do {

			XCHUNK_HDR *pchunkhdr = (XCHUNK_HDR*)((unsigned char*)file_contents + total_parsed_length);

			unsigned char *hdr_ptr = (unsigned char *)pchunkhdr;
			unsigned char *data_ptr = (unsigned char *)hdr_ptr + sizeof(XCHUNK_HDR);
			unsigned short data_len = htons(pchunkhdr->size);
			unsigned short chunk_index = htons(pchunkhdr->indx);

			ptr[chunk_index - 1] = (unsigned char*)malloc(data_len + sizeof(XCHUNK_HDR));
			memcpy(ptr[chunk_index - 1], hdr_ptr, data_len + sizeof(XCHUNK_HDR));

			total_parsed_length += data_len + sizeof(XCHUNK_HDR);
			chunk_index++;

		} while (total_parsed_length != file_length);


		for (int i = 0; i < total_chunks; i++){

			XCHUNK_HDR *pchunkhdr = (XCHUNK_HDR*)ptr[i];
			unsigned short data_len = htons(pchunkhdr->size);
		//	printf("defrag_file:save chunk index %d of chunk size %d\n", i, data_len);
		//	hexDump("hex", ptr[i], data_len + sizeof(XCHUNK_HDR));
			save2file(outputfile, (unsigned char*)(ptr[i]), data_len + sizeof(XCHUNK_HDR));
			free(ptr[i]);

		}


		free(ptr);
	}


	free(file_contents);

	return 1;
}







int decode_file(char *input_file, char *output_file)
{


	unsigned char * file_contents = 0;
	unsigned int file_length = -1;

	file_contents = read_whole_file(input_file, &file_length);

	if (!file_contents) return 0;
	printf("decode_file:length =%d\n", file_length);

	unsigned int total_parsed_length = 0;

	do{

		XCHUNK_HDR *pchunkhdr = (XCHUNK_HDR*)((unsigned char*)file_contents + total_parsed_length);

		if (pchunkhdr->magic != 0){

			if (pchunkhdr->magic & 0x0100) {
				pchunkhdr->fec_hdr[0] ^= 0xD0;
			}
			if (pchunkhdr->magic & 0x0200) {
				pchunkhdr->fec_hdr[2] ^= 0xD0;
			}
			if (pchunkhdr->magic & 0x0400) {
				pchunkhdr->fec_hdr[4] ^= 0xD0;
			}
			if (pchunkhdr->magic & 0x0800) {
				pchunkhdr->fec_hdr[6] ^= 0xD0;
			}

		}

		unsigned char *data_ptr = (unsigned char *)pchunkhdr + sizeof(XCHUNK_HDR);
		unsigned short data_len = htons(pchunkhdr->size);

		fec_init(8);
		uint8_t result = fec_decode(data_ptr, data_len, pchunkhdr->fec_hdr);
		if (FEC_UNCORRECTABLE_ERRORS == result) {

			hexDump("decode_file:chunk error", pchunkhdr, sizeof(XCHUNK_HDR)+data_len);
			printf("Return value if fec_decode cannot fix all errors offset %02X!!\n", total_parsed_length);
			free(file_contents);

			return 0;
		}
		if (FEC_CORRECTED_ERRORS == result){

			//printf("fec_decode chunk corrected chunk size %d \n", data_len);
		}

		save2file(output_file, data_ptr, data_len);


		total_parsed_length += data_len + sizeof(XCHUNK_HDR);

	} while (total_parsed_length != file_length);

	printf("decode file  is over\n");


	free(file_contents);

	return 1;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
// Executes the given command using CreateProcess() and WaitForSingleObject().
// Returns FALSE if the command could not be executed or if the exit code could not be determined.
BOOL executeCommandLine(char* cmdLine, DWORD & exitCode)
{
	PROCESS_INFORMATION processInformation = { 0 };
	STARTUPINFOA startupInfo = { 0 };
	startupInfo.cb = sizeof(startupInfo);
	int nStrBuffer = strlen(cmdLine) + 50;


	// Create the process
	BOOL result = CreateProcessA(NULL, cmdLine,
		NULL, NULL, FALSE,
		NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW,
		NULL, NULL, &startupInfo, &processInformation);



	if (!result)
	{
		// CreateProcess() failed
		// Get the error from the system
		LPVOID lpMsgBuf;
		DWORD dw = GetLastError();
		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpMsgBuf, 0, NULL);


		printf(("::executeCommandLine() failed at CreateProcess()\nCommand=%s\nMessage=%s\n\n"), cmdLine, lpMsgBuf);

		// Free resources created by the system
		LocalFree(lpMsgBuf);

		// We failed.
		return FALSE;
	}
	else
	{
		// Successfully created the process.  Wait for it to finish.
		WaitForSingleObject(processInformation.hProcess, INFINITE);

		// Get the exit code.
		result = GetExitCodeProcess(processInformation.hProcess, &exitCode);

		// Close the handles.
		CloseHandle(processInformation.hProcess);
		CloseHandle(processInformation.hThread);

		if (!result)
		{
			// Could not get exit code.
			printf("Executed command but couldn't get exit code.\nCommand=%s\n", cmdLine);
			return FALSE;
		}


		// We succeeded.
		return TRUE;
	}
}



#define NULL	0
#define EOF	(-1)
#define ERR(s, c)	if(opterr){\
	char errbuf[2]; \
	errbuf[0] = c; errbuf[1] = '\n'; \
	fputs(argv[0], stderr); \
	fputs(s, stderr); \
	fputc(c, stderr); }
//(void) write(2, argv[0], (unsigned)strlen(argv[0]));\
	//(void) write(2, s, (unsigned)strlen(s));\
	//(void) write(2, errbuf, 2);}

int	opterr = 1;
int	optind = 1;
int	optopt;
char	*optarg;

int getopt(int argc, char** argv, char*opts)

{
	static int sp = 1;
	register int c;
	register char *cp;

	if (sp == 1)
	if (optind >= argc ||
		argv[optind][0] != '-' || argv[optind][1] == '\0')
		return(EOF);
	else if (strcmp(argv[optind], "--") == NULL) {
		optind++;
		return(EOF);
	}
	optopt = c = argv[optind][sp];
	if (c == ':' || (cp = strchr(opts, c)) == NULL) {
		ERR(": illegal option -- ", c);
		if (argv[optind][++sp] == '\0') {
			optind++;
			sp = 1;
		}
		return('?');
	}
	if (*++cp == ':') {
		if (argv[optind][sp + 1] != '\0')
			optarg = &argv[optind++][sp + 1];
		else if (++optind >= argc) {
			ERR(": option requires an argument -- ", c);
			sp = 1;
			return('?');
		}
		else
			optarg = argv[optind++];
		sp = 1;
	}
	else {
		if (argv[optind][++sp] == '\0') {
			sp = 1;
			optind++;
		}
		optarg = NULL;
	}
	return(c);
}




BOOL DirectoryExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

BOOL FileExists(LPCTSTR szPath)
{
	DWORD dwAttrib = GetFileAttributes(szPath);

	return (dwAttrib != INVALID_FILE_ATTRIBUTES &&
		!(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}



int dump_file_chunks(char *input_file)
{


	unsigned char * file_contents = 0;
	unsigned int file_length = -1;

	file_contents = read_whole_file(input_file, &file_length);

	if (!file_contents) return 0;
	printf("decode_file:length =%d\n", file_length);

	XCHUNK_HDR *pchunkhdr = (XCHUNK_HDR*)((unsigned char*)file_contents);

	unsigned short data_len = htons(pchunkhdr->size);

	unsigned short total_bytes_parsed = 0;
	do{
		Sleep(100);

		pchunkhdr = (XCHUNK_HDR*)((unsigned char*)file_contents + total_bytes_parsed);
		unsigned short data_len = htons(pchunkhdr->size);
		printf("total bytes parsed=%d data_len=%d\n", total_bytes_parsed, data_len);

		if (data_len == 0x6C){



			hexDump("chunk", pchunkhdr, 0x6C + 18);
			total_bytes_parsed += 0x6C + sizeof(XCHUNK_HDR);

			continue;
		}
		if (data_len == 4){

			for (int i = 0; i < 4; i++){


				hexDump("chunk", pchunkhdr, 132);
				total_bytes_parsed += 132;




			}

			hexDump("chunk", pchunkhdr, 66);

			total_bytes_parsed += 66;

			continue;
		}

		if (data_len % 2) data_len++;

		if ((data_len + 18) == file_length - total_bytes_parsed){

			hexDump("chunk", pchunkhdr, data_len + 18);
			total_bytes_parsed += data_len + 18;
			printf("print last chunkk....");

		}





	} while (total_bytes_parsed != file_length);



	free(file_contents);



}

int encode_to_tar_bz2(char *input, char*output = "package.tar",int enable_bz2=1)
{

	DWORD dwExitCode = -1;
	char sztarcommand[0x100];
	sprintf(sztarcommand, "tar -cvpf %s %s", output, input);

	if (!executeCommandLine(sztarcommand, dwExitCode))
	{
		printf("[!] encode_to_tar_bz2 failed to create tar archive of the folder\n");
		return 0;

	}
	char szbzip2command[MAX_PATH] = { 0 };
	char szOutputfile[MAX_PATH] = { 0 };
	sprintf(szbzip2command, "bzip2 %s", output);

	if (enable_bz2){

		if (!executeCommandLine(szbzip2command, dwExitCode))
		{
			printf("[!] encode_to_tar_bz2 failed to create bz2 archive of the tar archive.\n");
			return 0;

		}
		
		sprintf(szOutputfile, "%s.bz2", output);
	}
	else{

	
		
		sprintf(szOutputfile, "%s", output);
	}

	
	

	return FileExists(szOutputfile);


}
int encode_to_bz2(char *input, char *output)
{
	DWORD dwExitCode = -1;
	char szbzip2command[0x100];

	sprintf(szbzip2command, "bzip2 %s", input);

	if (!executeCommandLine(szbzip2command, dwExitCode))
	{
		printf("[!] encode_to_bz2 failed to create bz2 archive of the file .\n");
		return 0;

	}
	char szBZ2file[MAX_PATH];
	sprintf(szBZ2file, "%s.bz2", input);
	return MoveFile(szBZ2file, output);

}


unsigned char g_ssidname[256];
int _tmain(int argc, char* argv[])
{

	
	
	_CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
	int aflag = 0;
	int bflag = 0;
	char *cvalue = NULL;
	int index;
	int c;

	opterr = 0;
	int disable_tar_bz2 = 0;
	int enable_bz2_compression = 0;

	int reboot = 0;
	
	if (((CHUNKS_SIZE) % 4) != 0){

		printf("Error: chunk size must be divded by 4 !");
		return -1;
	}


	while ((c = getopt(argc, argv, "r:c:s:f:d:")) != -1)
		switch (c)
	{
		case 'r':

			reboot = 1;
			break;
		case 'z':
			enable_bz2_compression = 1;
			break;
		case 'c':
			disable_tar_bz2 = 1;

			printf("parsing file with no bz2/tar compression [%s] ...\n", optarg);
			lstrcpy(g_szFileToBZ2, optarg);
			break;


		case 's':

			printf("parsing ssid name[%s]\n", optarg);
			lstrcpy((char*)g_ssidname, optarg);
			break;
		case 'f':
			printf("parsing file to BZ2 package [%s] ...\n", optarg);
			lstrcpy(g_szFileToBZ2, optarg);
			break;

		case 'd':

			printf("parsing folder to BZ2 package ...\n");
			lstrcpy(g_szDirectoryToTar, optarg);
			break;
		case '?':
			if (optopt == 'c')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr,
				"Unknown option character `\\x%x'.\n",
				optopt);
			return 1;
		default:
			abort();
	}
	DeleteFileA(PHP_FILE_PATH);
	DeleteFileA(ENCODED_OUTPUT_PATH);
	DeleteFileA(DECODED_OUTPUT_PATH);
	DeleteFileA(DEFRAG_FILE_PATH);



	
	DeleteFileA("package.tar.bz2"); // folder package encoded 
	DeleteFileA("package.bz2");  //file package encoded


	if (reboot){

		unsigned char *reboot_sms_ptr = encode_reboot(0, 0);

		DeleteFileA("reboot.bin");
		DeleteFileA("reboot.php");
		save2file("reboot.bin", reboot_sms_ptr, sizeof(XCOMMAND_HDR));
		create_php_script("reboot.bin", "reboot.php", "sms_reboot");
		free(reboot_sms_ptr);
		
		printf("flashing reboot script to reboot.php.");
		return 0;
	}

	if (g_ssidname[0] ){

	
		unsigned short ssid_length;
		unsigned char *pssid = encode_ssid(g_ssidname, &ssid_length);


		DeleteFileA(SSID_FILE_BIN);
		DeleteFileA(SSID_FILE_SCRIPT);
		save2file(SSID_FILE_BIN, pssid, ssid_length);
		create_php_script(SSID_FILE_BIN, SSID_FILE_SCRIPT, "sms_ssid");

		free(pssid);

		return 0;

	}

	if (!DirectoryExists(g_szDirectoryToTar) && !FileExists(g_szFileToBZ2)){

		printf("requires an argument of a folder or file to bz2 . \n");
		return -1;
	}

	char sz_package2encode[MAX_PATH];
	
	if (g_szDirectoryToTar[0]){

		if (!encode_to_tar_bz2(g_szDirectoryToTar, "package.tar", enable_bz2_compression)){
			
			printf("failed to tar the folder to tar.bz2 archive \n");
			return -1;
		}

		printf("success to compress  the folder to tar.bz2.\n");

		if (enable_bz2_compression){
			lstrcpy(sz_package2encode, "package.tar.bz2");
		}
		else{
			lstrcpy(sz_package2encode, "package.tar");
		}


	}
	else if (g_szFileToBZ2[0] && (disable_tar_bz2==0)){

		if (!encode_to_bz2(g_szFileToBZ2, "package.bz2")){


			printf("failed to bz2 file to  bz2 archive \n");
			return -1;
		}

		printf("success to compress  the file to .bz2\n");
		lstrcpy(sz_package2encode, "package.bz2");
		

	}
	else if (disable_tar_bz2 == 1){

		printf("parsing without compression ...\n");
		lstrcpy(sz_package2encode, g_szFileToBZ2);
	
	}


	if (disable_tar_bz2 == 0){
		if (!FileExists("package.tar.bz2") && !FileExists("package.bz2") && !FileExists("package.tar")  ){

			printf("failed to create the final bz2 package for encoding.\n");
			return -1;
		}
	}



	char outputfile[MAX_PATH];
	sprintf(outputfile, ENCODED_OUTPUT_PATH);


	printf("we encoding the file [%s]\n", sz_package2encode);

	if (encode_file(sz_package2encode, outputfile, CHUNKS_SIZE)){  //sms limit 160 our header is 18 byte long 

		printf("[*]encode_file:OK\n");
	}
	else {
		printf("encode_file result ERROR\n");

		return -1;
	}

	if (verify_file(outputfile)){

		printf("\nverify_file:OKAY\n");


		defrag_file(outputfile, DEFRAG_FILE_PATH);
		decode_file(outputfile, DECODED_OUTPUT_PATH);
		create_php_script(outputfile, PHP_FILE_PATH);

	}
	else{

		printf("verify_file:FAILED!");
		Sleep(1111);
		return -1;
	}

	Sleep(1111);


	return 0;
}

