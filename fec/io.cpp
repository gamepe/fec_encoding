
#include "stdafx.h"
#include<Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* calloc, exit, free */

/* This routine returns the size of the file it is called with. */

unsigned
get_file_size(const char * file_name)
{
	struct stat sb;
	if (stat(file_name, &sb) != 0) {

		return 0;
	}
	return sb.st_size;
}

/* This routine reads the entire file into memory. */

 unsigned char *
read_whole_file(const char * file_name, unsigned int* plength)
{
	unsigned int s;
	unsigned char * contents;
	FILE * f;
	size_t bytes_read;
	int status;
	
	s = get_file_size(file_name);

	contents = (unsigned  char*)malloc(s);
	if (!contents) {
		printf("Not enough memory.\n");
	
		return 0;
	}

	*plength = s;
	f = fopen(file_name, "rb");
	if (!f) {

		free(contents);
		printf("Could not open '%s': %s.\n", file_name,strerror(errno));

		return 0;
	}

	bytes_read = fread(contents, sizeof (unsigned char), s, f);

	if (bytes_read != s) {

		printf( "Short read of '%s': expected %d bytes "
			"but got %d: %s.\n", file_name, s, bytes_read,
			strerror(errno));

		free(contents);
		return 0;
	}

	status = fclose(f);
	if (status != 0) {
		printf( "Error closing '%s': %s.\n", file_name,
			strerror(errno));
		free(contents);
		return 0;
	}
	return contents;
}
#pragma comment(lib, "ws2_32.lib")


void hexDump(char *desc, void *addr, int len) {
	int i;
	unsigned char buff[17];
	unsigned char *pc = (unsigned char*)addr;

	// Output description if given.
	if (desc != NULL)
		printf("%s:\n", desc);

	// Process every byte in the data.
	for (i = 0; i < len; i++) {
		//Sleep(10);
		// Multiple of 16 means new line (with line offset).

		if ((i % 16) == 0) {
			// Just don't print ASCII for the zeroth line.
			if (i != 0) {
				printf("  %s\n", buff);


			}

			// Output the offset.
			printf("  %04x ", i);
		}

		// Now the hex code for the specific character.
		printf(" %02x", pc[i]);

		// And store a printable ASCII character for later.
		if ((pc[i] < 0x20) || (pc[i] > 0x7e))
			buff[i % 16] = '.';
		else
			buff[i % 16] = pc[i];
		buff[(i % 16) + 1] = '\0';
	}

	// Pad out last line if not exactly 16 characters.
	while ((i % 16) != 0) {
		printf("   ");
		i++;
	}


	// And print the final ASCII bit.
	printf("  %s\n", buff);

}
