#include "dumpcode.h"

void printchar(const unsigned char c)
{
	if(isprint(c))
		printf("%c", c);
	else
		printf(".");
}

void dumpcode(const unsigned char *buf, int len)
{
	int i;
	for (i = 0; i < len; i++)
	{
		printf("%02x ", buf[i]);

		if (i % 16 - 15 == 0)
		{
			int j;
			printf("  ");
			for (j = i - 15; j <= i; j++)
				printchar(buf[j]);
			printf("\n");
		}
	}

	if (i % 16 != 0)
	{
		int j;
		int spaces = (len - i + 16 - i % 16) * 3 + 2;
		for (j = 0; j < spaces; j++)
			printf(" ");

		for (j = i - i % 16; j < len; j++)
			printchar(buf[j]);
	}
	printf("\n");
}

