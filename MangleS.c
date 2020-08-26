#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
<<<<<<< HEAD
=======
#include <stdlib.h>
#include <ctype.h>
>>>>>>> f252570... Added HelloWorld.c

#define ELFHeaderLength 0x40
#define ProgramHeaderLength 0x38
#define SectionheaderLength 0x40
<<<<<<< HEAD
#define Offset 56
// above is the length of string "address           perms offset  dev   inode   pathname\n"
// It's at the top of /proc/self/maps
=======
#define AddressLength 12
#define fileLineSize 100
>>>>>>> f252570... Added HelloWorld.c
typedef int WORD;

void searchAndDestroy(void)
{
<<<<<<< HEAD
	// Get address space
	int fileDescriptor;
	char* map[2];
	WORD *start;
	WORD *end;

	// open /proc/self/map to read address space
	fileDescriptor = open("/proc/self/maps", O_RDONLY);
	// set offset to 57 and read next bytes into char pointer at map[0], skip the dash, and read next into char pointer at map[1]
	lseek(fileDescriptor, Offset, SEEK_CUR);
	read(fileDescriptor, map[0], 8);
	lseek(fileDescriptor, 1, SEEK_CUR);
	read(fileDescriptor, map[1], 8);
	// map now contains two char pointers; one to the start address, one to the end address

	// sscanf the char in map[0] to hexadecimal values to be pointers start and end
	sscanf(map[0], "%x", start);
	sscanf(map[1], "%x", end);

	// clear ELF & Program Headers
	for (int i = 0; i <= ELFHeaderLength + ProgramHeaderLength; i++)
	{
		*(start + i) = 0x00;
=======
	FILE *filePointer;
	char *line;
	char address[AddressLength + 1];
	WORD *start;
	WORD *end;

	// open /proc/self/maps file
	filePointer = fopen("/proc/self/maps", "r");
	if (filePointer == NULL)
	{
		fprintf(stderr, "\t[X] Failed to open /proc/self/maps, exiting now...\n");
		exit(1);
	}
	printf("\t[*] Opened /proc/self/maps\n");
	// start should store the characters from the first line that reads MangleS.elf through to the "-"
	// if strstr(line, "MangleS.elf") != NULL, 


	// clear ELF & Program Headers
	/*
	for (int i = 0; i <= ELFHeaderLength + ProgramHeaderLength; i++)
	{
		*(start + i) = 0x00;
		printf("\t[*] Clearing address %p\n", start + i);
>>>>>>> f252570... Added HelloWorld.c
	}
	// clear Section Header
	for (int i = SectionheaderLength; i >= 0; i--)
	{
<<<<<<< HEAD
		*(end + i) = 0x00;
	}
=======
		printf("\t[*] Clearing address %p\n", end + i);
		*(end + i) = 0x00;
	}
	*/
>>>>>>> f252570... Added HelloWorld.c

}

int main(void)
{
	searchAndDestroy();

	// do evil
<<<<<<< HEAD
	while (TRUE)
=======
	while (1)
>>>>>>> f252570... Added HelloWorld.c
	{
		printf("\t[*] Doing Evil");
		sleep(3);
	}	
}

