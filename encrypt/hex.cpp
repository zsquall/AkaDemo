#include <string.h>
#include "hex.hpp"

static int CharToInt(unsigned char c)
{
    if(c >= '0' && c <= '9')
    {
        return c - '0';
    }
    else if(c >= 'a' && c <= 'z')
    {
        return c - 'a' + 10;
    }
}
static char intToChar(int i)
{
    if(i <= 9)
    {
        return i + '0';
    }
    else
    {
        return i - 10 + 'a';
    }
}

int hexStrToBin(unsigned char* source, unsigned char* obj)
{
    int j = 0;
    for(int i = 0; i < strlen((char*)source); i ++)
    {
        j = i/2;
        int k = i % 2;
        obj[j] = (obj[j] << 4) | (CharToInt(source[i])) ;
    }
    return j+1;
}

void binToHex(unsigned char* source, int in_len, unsigned char* obj)
{
    int j = 0;
    for(int i =0; i < in_len; i++)
    {
        int big = source[i] >> 4;
        int small = source[i] & 0x0F;
        obj[j] = intToChar(big);
        obj[j+1] = intToChar(small);
        j+=2;
    }
    obj[j] = '\0';
}
