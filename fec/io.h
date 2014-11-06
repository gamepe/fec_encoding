
#pragma once 

void hexDump(char *desc, void *addr, int len);

unsigned char *
read_whole_file(const char * file_name, unsigned int* plength);

unsigned
get_file_size(const char * file_name);
