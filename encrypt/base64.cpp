#include <stdio.h>
#include <string.h>
char* bstr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
void base64_encode(unsigned char* input, int length, unsigned char* output)
{
    int i = 0;
    int o = 0;
    while (i < length)
    {
        int remain = length - i;
        switch (remain)
        {
            case 1:
                output[o++] = bstr[((input[i] >> 2) & 0x3f)];
                output[o++] = bstr[((input[i] << 4) & 0x30)];
                output[o++] = '=';
                output[o++] = '=';
                break;
            case 2:
                output[o++] = bstr[((input[i] >> 2) & 0x3f)];
                output[o++] = bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
                output[o++] =  bstr[((input[i + 1] << 2) & 0x3c)];
                output[o++] =  '=';
                break;
            default:
                output[o++] = bstr[((input[i] >> 2) & 0x3f)];
                output[o++] = bstr[((input[i] << 4) & 0x30) + ((input[i + 1] >> 4) & 0x0f)];
                output[o++] = bstr[((input[i + 1] << 2) & 0x3c) + ((input[i + 2] >> 6) & 0x03)];
                output[o++] = bstr[(input[i + 2] & 0x3f)];
        }
        i += 3;
    }
    output[o] = '\0';
}
static int codetovalue(unsigned char c)
{
    if( (c >= (unsigned char)'A') && (c <= (unsigned char)'Z') )
    {
        return (int)(c - (unsigned char)'A');
    }
    else if( (c >= (unsigned char)'a') && (c <= (unsigned char)'z') )
    {
        return ((int)(c - (unsigned char)'a') +26);
    }
    else if( (c >= (unsigned char)'0') && (c <= (unsigned char)'9') )
    {
        return ((int)(c - (unsigned char)'0') +52);
    }
    else if( (unsigned char)'+' == c )
    {
        return (int)62;
    }
    else if( (unsigned char)'/' == c )
    {
        return (int)63;
    }
    else
    {
        return -1;
    }
}

static int decode4to3( const unsigned char *src,unsigned char *dest)
{
    int b32 = 0;
    int bits;
    int i;

    for( i = 0; i < 4; i++ )
    {
        bits = codetovalue(src[i]);
        if( bits < 0 )
        {
            return 0;
        }

        b32 <<= 6;
        b32 |= bits;
    }

    dest[0] = (unsigned char)((b32 >> 16) & 0xFF);
    dest[1] = (unsigned char)((b32 >>  8) & 0xFF);
    dest[2] = (unsigned char)((b32      ) & 0xFF);

    return 1;
}

static int decode3to2(const unsigned char *src,unsigned char *dest)
{
    int b32 = (int)0;
    int bits;
    int ubits;

    bits = codetovalue(src[0]);
    if( bits < 0 )
    {
        return 0;
    }

    b32 = (int)bits;
    b32 <<= 6;

    bits = codetovalue(src[1]);
    if( bits < 0 )
    {
        return 0;
    }

    b32 |= (int)bits;
    b32 <<= 4;

    bits = codetovalue(src[2]);
    if( bits < 0 )
    {
        return 0;
    }

    ubits = (int)bits;
    b32 |= (ubits >> 2);

    dest[0] = (unsigned char)((b32 >> 8) & 0xFF);
    dest[1] = (unsigned char)((b32     ) & 0xFF);

    return 1;
}

static int decode2to1(const unsigned char *src,unsigned char *dest)
{
    int b32;
    int ubits;
    int bits;

    bits = codetovalue(src[0]);
    if( bits < 0 )
    {
        return 0;
    }

    ubits = (int)bits;
    b32 = (ubits << 2);

    bits = codetovalue(src[1]);
    if( bits < 0 )
    {
        return 0;
    }

    ubits = (int)bits;
    b32 |= (ubits >> 4);

    dest[0] = (unsigned char)b32;

    return 1;
}

static int decode(const unsigned char *src, int srclen, unsigned char *dest)
{
    int rv;
    int dest_len = 0;

    while( srclen >= 4 )
    {
        rv = decode4to3(src, dest);
        if( 1 != rv )
        {
            return 0;
        }

        src += 4;
        dest += 3;
        srclen -= 4;
        dest_len += 3;
    }

    switch( srclen )
    {
        case 3:
            rv = decode3to2(src, dest);
            dest_len += 2;
            break;
        case 2:
            rv = decode2to1(src, dest);
            dest_len += 1;
            break;
        case 1:
            rv = 0;
            break;
        case 0:
            rv = 1;
            break;
        default:
            printf("coding error");
    }

    return dest_len;
}


int base64_decode(unsigned char *src, unsigned char *dest)
{
    int status;
    int allocated = 0;
    int srclen = strlen((char*)src);

    if( (unsigned char)'=' == src[ srclen-1 ] )
    {
        if( (unsigned char)'=' == src[ srclen-2 ] )
        {
            srclen -= 2;
        }
        else
        {
            srclen -= 1;
        }
    }

    return decode((const unsigned char *)src, srclen, (unsigned char *)dest);
}
