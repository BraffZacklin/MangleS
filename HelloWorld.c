#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile char first_letter = '\a';

void firstPrint(void)
{
	volatile int i = rand();
	
	int offset = i - i + 65;
	volatile char second_letter = offset + 36;
	volatile char third_letter = second_letter + 7;
	
	// array is "Hel\0"
	char output[4] = {first_letter + offset, second_letter, third_letter};

	printf("%s", output);
}

void secondPrint(void)
{
	// Maths that we know the outcome of, usually simplified by compiler, but the volatile keyword directs it to not do so
	volatile int i = 100;
	volatile int j = 21;

	// this sets i to 108
	i = i / 2;
	i = i * 2 + i % 49;
	i = i + 7;

	// array is of "lo W\0"
	char output[5] = {i, i+3, j+11, i-j};
	printf("%s", output);
}


void thirdPrint(void)
{
	char key[] = "XOROX";
	char ciphertext[] = {55, 61, 62, 43, 121, 0};
	int len = (int) (sizeof(ciphertext) / sizeof(char));
	
	for (int i = 0; i < len; i++)
	{
		char c = key[i] ^ ciphertext[i];
		printf("%c", c);
	}
}

int main(void)
{
	// junk initialises for impossible to occur else execve and also a sleep with random time function
	char * array[2];
	array[0] = "/bin/sh";
	array[1] = NULL;

	volatile int i = 2;

	if (rand() + 1 > 1)
		sw: switch(i)
		{
		// all these statements will be executed, but the program's control flow becomes "flattened"
			case 0: secondPrint();
			i = 1;
			goto sw;
			case 1: thirdPrint();
			i = rand();
			break;
			case 2: firstPrint();
			i = 0;
			goto sw;
		}
	// as randOver1 is always greater than 1, these will never execute; they are still compiled, however, as the entropy makes it impossible for the compiler to tell
	else if (i - i > 0)
		execve(array[0], array, NULL);
	else
		sleep(rand());

	printf("\n");
	i = rand();
	return(i - i);
}

