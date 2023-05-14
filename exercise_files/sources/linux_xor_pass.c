#include <stdio.h>
#include <string.h>

int main()
{
	//encrypted string
	const char s[20]="_n||x`}k>=<.";

	//xor key
	const short m = 0x0f;

	char k[20]="";

	for(int i=0;i<strlen(s);i++)
	{
		k[i] = s[i] ^ m;
	}

	printf("%s\n",k);
	return 0;
}
