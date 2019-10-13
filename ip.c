#include<stdio.h>

#include<stdlib.h>

#include<string.h>

void toStringIP(const unsigned int ip, char* stringIP);

int main()

{

	unsigned int ip = 1338378;

	char* stringIP = (char*)malloc(16);

	memset(stringIP, 0, 16 + 1);

	toStringIP(ip, stringIP);

	puts(stringIP);

	return 0;

}



void toStringIP(const unsigned int ip, char* stringIP)

{



	unsigned int tempIP = ip;

	for (int i = 0; i < 3; i++)

	{

		unsigned char part = (char)tempIP;

		char temp[4];



		sprintf(temp, "%d.", part);



		strcat(stringIP, temp);



		tempIP = tempIP >> 8;



	}

	unsigned char part = (char)tempIP;

	char temp[4];

	sprintf(temp, "%d", part);

	strcat(stringIP, temp);



}