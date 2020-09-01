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
#define ELFHeaderLength 0x40
#define ProgramHeaderLength 0x38
#define SectionHeaderLength 0x40
#define AddressLength 12
#define SecondAddressOffset (AddressLength + 1)
#define FileLineBuff 150
#define HexOffset 2
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
	char address[AddressLength + 1];
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
	fgets(line, FileLineBuff, filePointer);
	memcpy(address, line + HexOffset, AddressLength * (sizeof(char)));
	printf("\t[*] Start Address Str Found: 0x%s\n", address);

	// make pointer
	start = (WORD *) address;
	printf("\t[*] Start Address Found: %p\n", start);

	// trace through until the last line is found... a bit of wasted computing power to read the second address in constantly, but sue me
	for (char lastLine[FileLineBuff]; (strstr(line, "MangleS.elf")) != NULL; fgets(line, FileLineBuff, filePointer))
	{
		memcpy(address, lastLine + HexOffset + SecondAddressOffset, AddressLength * (sizeof(char)));
	}
	printf("\t[*] End Address Str Found: 0x%s\n", address);

	// make pointer
	end = (WORD *) address;
	printf("\t[*] End Address Found: %p\n", end);

	// close file stream
	fclose(filePointer);

	// allow write to header spaces with mprotect
	mprotect(start, (size_t) end - (size_t) start, PROT_WRITE);
	// clear ELF & Program Headers
	for (int i = 0; i < (ELFHeaderLength + ProgramHeaderLength); i++)
	{
		*(start + i) = 0x00;
		printf("\t[*] Clearing start address <+%d>%p\n", i, start + i);
	}
	mprotect(start, (size_t) ELFHeaderLength + (size_t) ProgramHeaderLength, PROT_NONE);
	// clear Section Header

	for (int i = 0; i < SectionHeaderLength; i++)
	{
		*(end + i) = 0x00;
		printf("\t[*] Clearing end address <+%d>%p\n", i, end + i);
	}
	mprotect(start, (size_t) end - (size_t) start, PROT_NONE);

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

	// Check resolution against 1024*768; VBox default
	if (DisplayWidth(display, 0) == 1024)
	{
		if (DisplayHeight(display, 0) == 768)
		{
			XCloseDisplay(display);
			return 1;
		}
	}
	XCloseDisplay(display);
	return 0;

}

int BlockSpook(int *devices)
{
	FILE *filePointer;
	char blockOut[1000];
	int i = 0;

	filePointer = popen("/bin/lsblk", "r");
	if (filePointer == NULL) 
	{
		return BlockSpookError;
	}
	while (fgets(blockOut, sizeof(blockOut), filePointer) != NULL) 
	{
		i++;
	}
	if (*devices == 0 || *devices > i)
	{
		fclose(filePointer);
		*devices = i;
		return 0;
	}
	else if (*devices < i)
	{
		fclose(filePointer);
		return 1;
	}
	else
	{
		fclose(filePointer);
		return 0;
	}
}

int SelfDestruct(void)
{
	FILE *filePointer;
	char linkDir[LinkBuff];
	char *linkName = "/proc/self/exe";
	char rmCommand[RMLength + LinkBuff] = "rm ";
	char shredCommand[shredLength + LinkBuff] = "shred ";

	// open /proc/self/exe 
	filePointer = popen(linkName, "r");
	if (filePointer == NULL)
	{
		fclose(filePointer);
		return SelfDestructError;
	}

	// read the symlink and close file
	realpath(linkName, linkDir);
	fclose(filePointer);

	// execute shred command
	strcat(rmCommand, linkName);
	strcat(shredCommand, linkName);
	system(rmCommand);
	system(shredCommand);
	
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
			return 0;			
		case SpookAssert:
			printf("\t[X] Spook Found, Abourting\n");
			spookError = SelfDestruct();
			goto sw;
		case SearchAndDestroyError:
			printf("\t[X] SearchAndDestroyError, Aborting\n");
			spookError = SelfDestruct();
			goto sw;
		case VMSpookError:
			printf("\t[X] VMSpookError, Aborting\n");
			spookError = SelfDestruct();
			goto sw;
		case BlockSpookError:
			printf("\t[X] BlockSpookError, Aborting\n");
			goto sw;
		case SelfDestructError:
			printf("\t[X] SelfDestructError, Exiting\n");
			exit(1);
	}
}

int main(void)
{	
	int *devices;

	SpookHandle(VMSpook());
	SpookHandle(SearchAndDestroy());

	// do evil
	while (1)
	{
		SpookHandle(BlockSpook(devices));

		printf("\t[*] Doing Evil\n");
		sleep(1);		
	}	

}