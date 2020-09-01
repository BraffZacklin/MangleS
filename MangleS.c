#include <stdio.h> 
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <X11/Xlib.h>

#define RM_LEN 3
#define SHRED_LEN 6
#define PATH_BUFF 150

#define ELF_HLEN 0x40
#define PROGRAM_HLEN 0x38
#define SECTION_HLEN 0x40
#define ADDR_LEN 12
#define END_ADDR_OFF (ADDR_LEN + 1)

#define FILE_READ_BUFF 150
typedef char BYTE;

#define NoSpooks 0
#define SpookAssert 1
#define SearchAndDestroyError 2
#define VMSpookError 3
#define BlockSpookError 41
#define SelfDestructError 5

int SearchAndDestroy(void)
{
	FILE *filePointer;
	char line[FILE_READ_BUFF];
	char lastLine[FILE_READ_BUFF];
	char addressStr[ADDR_LEN + 1];
	char programPath[PATH_BUFF];
	long int addressInt;
	BYTE *start;
	BYTE *end;

	// open /proc/self/maps file
	filePointer = fopen("/proc/self/maps", "r");
	if (filePointer == NULL)
	{
		return SearchAndDestroyError;
	}
	printf("\t[*] Opened /proc/self/maps\n");

	// read /proc/self/exe for filename
	realpath("/proc/self/exe", programPath);
	
	// read the first address from first line from /proc/self/maps into address array  
	while (fgets(line, FILE_READ_BUFF * sizeof(char), filePointer))
	{
		if ((strstr(line, programPath)) != NULL) 
			break;
	}

	memcpy(addressStr, line, ADDR_LEN);
	addressStr[ADDR_LEN] = 0x00;
	printf("\t[*] Start Address Str Found: 0x%s\n", addressStr);

	// make hex then make pointer
	addressInt = strtol(addressStr, NULL, 16);
	printf("\t[*] Start Address Int Found: %lx\n", addressInt);
	start = (BYTE *) addressInt;
	printf("\t[*] Start Address Found: %p\n", start);

	// trace through until the last line is found
	for (; (strstr(line, programPath)) != NULL; fgets(line, FILE_READ_BUFF * sizeof(char), filePointer))
	{
		memcpy(lastLine, line, FILE_READ_BUFF);
	}
	memcpy(addressStr, &lastLine[END_ADDR_OFF], ADDR_LEN);
	addressStr[ADDR_LEN] = 0x00;
	printf("\t[*] End Address Str Found: 0x%s\n", addressStr);

	// make hex then make pointer
	addressInt = strtol(addressStr, NULL, 16);
	printf("\t[*] Start Address Int Found: %lx\n", addressInt);
	end = (BYTE *) addressInt;
	printf("\t[*] End Address Found: %p\n", end);

	// close file stream
	fclose(filePointer);

	// allow write to header spaces with mprotect
	mprotect(start, ELF_HLEN + PROGRAM_HLEN, PROT_WRITE);

	// clear ELF & Program Headers
	for (int i = 0; i < (ELF_HLEN + PROGRAM_HLEN); i++)
	{
		*(start + i) = 0;
		printf("\t[*] Clearing start address <+%02x>%p\n", i, start + i);
	}
	printf("\t[*] Done Flushing ELF and Program Headers\n");

	// disallow write & allow SectionHeader write
	mprotect(start, ELF_HLEN + PROGRAM_HLEN, PROT_READ);
	printf("\t[*] Disabled write to ELF and Program Headers\n");
	mprotect(end - SECTION_HLEN, SECTION_HLEN, PROT_WRITE);
	printf("\t[*] Enabled write to Section Header\n");

	// clear Section Header
	for (int i = 0; i < SECTION_HLEN; i++)
	{
		*(end - SECTION_HLEN + i) = 0;
		printf("\t[*] Clearing end address <+%02x>%p\n", i, end + i);
	}
	printf("\t[*] Done Flushing Section Headers\n");
	mprotect(end - SECTION_HLEN, SECTION_HLEN, PROT_READ);
	printf("\t[*] Disabled write to Section Header\n");
	return 0;
}

int VMSpook(void)
{
	Display *display;
	char *displayName = NULL;

	// get display connection
	display = XOpenDisplay(displayName);
	if (!display)
	{
		return VMSpookError;
	}

	printf("\t[*] Opened XDisplay\n\t\tWidth = %d\n\t\tHeight = %d\n", DisplayWidth(display, 0), DisplayHeight(display, 0));
	// Check resolution against 1024*768; VBox default
	if (DisplayWidth(display, 0) == 1024)
	{
		if (DisplayHeight(display, 0) == 768)
		{
			XCloseDisplay(display);
			printf("\t[X] VM Resolution Fingerprint Found\n");
			return 1;
		}
	}
	printf("\t[*] No VM Resolution Fingerprint Found\n");
	XCloseDisplay(display);
	return 0;
}

int BlockSpook(int *devices)
{
	FILE *filePointer = NULL;
	char blockOut[FILE_READ_BUFF];
	int i = 0;

	printf("\t[*] Running lsblk\n");
	filePointer = popen("/bin/lsblk", "r");
	if (filePointer == NULL) 
	{
		return BlockSpookError;
	}
	while (fgets(blockOut, FILE_READ_BUFF * sizeof(char), filePointer) != NULL) 
	{
		i++;
	}
	printf("\t[*] lsblk returned %d line(s)", i);
	if (*devices == 0 || *devices > i)
	{
		pclose(filePointer);
		*devices = i;
		return 0;
	}
	else if (*devices < i)
	{
		printf("\t[X] Block Device Inserted, Terminating\n");
		pclose(filePointer);
		return 1;
	}
	else
	{
		pclose(filePointer);
		return 0;
	}
}

int SelfDestruct(void)
{
	printf("\t[X] Spook Found, Self Destructing...\n");
	FILE *filePointer;
	char programPath[PATH_BUFF];
	char rmCommand[RM_LEN + PATH_BUFF] = "rm ";
	char shredCommand[SHRED_LEN + PATH_BUFF] = "shred ";

	// read the symlink and close file
	realpath("/proc/self/exe", programPath);
	
	printf("\t[*] Found Exe Location %s", programPath);
	// execute shred command
	strcat(rmCommand, programPath);
	strcat(shredCommand, programPath);
	system(shredCommand);
	system(rmCommand);
	printf("\t[*] Successfully Shredded and Rm'd File\n");

	exit(0); 
}

int SpookHandle(int spookError)
{
	sw: switch(spookError)
	{
		case NoSpooks:
			break;		
		case SpookAssert:
			printf("\t[X] Spook Found, Exiting\n");
			spookError = SelfDestruct();
			goto sw;
		case SearchAndDestroyError:
			printf("\t[X] SearchAndDestroyError, Exiting\n");
			spookError = SelfDestruct();
			goto sw;
		case VMSpookError:
			printf("\t[X] VMSpookError, Exiting\n");
			spookError = SelfDestruct();
			goto sw;
		case BlockSpookError:
			printf("\t[X] BlockSpookError, Exiting\n");
			spookError = SelfDestruct();
			goto sw;
		case SelfDestructError:
			printf("\t[X] SelfDestructError, Exiting\n");
			exit(1);
	}
	return 0;
}

int main(void)
{	
	int *devices = 0;

	SpookHandle(VMSpook());
	SpookHandle(SearchAndDestroy());
	
	// do evil
	while (1)
	{
		SpookHandle(BlockSpook(devices));
		printf("\t[*] Doing Evil\n");
		sleep(1);
	}	
	return 0;
}