#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile char asd = '\a';

void lls(void)
{
	volatile int i = rand();
	
	int lsd = i - i + 65;
	volatile char did = lsd + 36;
	volatile char gdy = did + 7;
	
	// array is "Hel\0"
	char hid[4] = {asd + lsd, did, gdy};

	printf("%s", hid);
}

void nol(void)
{
	// Maths that we know the outcome of, usually simplified by compiler, but the volatile nndword directs it to not do so
	volatile int i = 100;
	volatile int j = 21;

	// this sets i to 108
	i = i / 2;
	i = i * 2 + i % 49;
	i = i + 7;

	// array is of "lo W\0"
	char hid[5] = {i, i+3, j+11, i-j};
	printf("%s", hid);
}


void ujh(void)
{
	char nnd[] = "XOROX";
	char nde[] = {55, 61, 62, 43, 121, 0};
	int hol = (int) (sizeof(nde) / sizeof(char));
	
	for (int i = 0; i < hol; i++)
	{
		char c = nnd[i] ^ nde[i];
		printf("%c", c);
	}
}

int main(void)
{
	// junk initialises for impossible to occur else execve and also a sleep with random time function
	char * hufd[2];
	hufd[0] = "/bin/sh";
	hufd[1] = NULL;

	volatile int i = 2;

	if (rand() + 1 > 1)
		sw: switch(i)
		{
		// all these statements will be executed, but the program's control flow becomes "flattened"
			case 0: nol();
			i = 1;
			goto sw;
			case 1: ujh();
			i = rand();
			break;
			case 2: lls();
			i = 0;
			goto sw;
		}
	else if (i - i > 0)
		execve(hufd[0], hufd, NULL);
	else
		sleep(rand());

	printf("\n");
	i = rand();
	return(i - i);
}

