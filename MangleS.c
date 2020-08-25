#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#define ELFHeaderLength 0x40
#define ProgramHeaderLength 0x38
#define SectionheaderLength 0x40
#define Offset 56
// above is the length of string "address           perms offset  dev   inode   pathname\n"
// It's at the top of /proc/self/maps
typedef int WORD;

void searchAndDestroy(void)
{
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
	}
	// clear Section Header
	for (int i = SectionheaderLength; i >= 0; i--)
	{
		*(end + i) = 0x00;
	}

}

int main(void)
{
	searchAndDestroy();

	// do evil
	while (TRUE)
	{
		printf("\t[*] Doing Evil");
		sleep(3);
	}	
}

