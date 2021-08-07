#include "digest.hpp"
#include <string.h>
#include <stdlib.h>

void Digest::Hmac(unsigned char* text, int text_len, unsigned char* key, int key_len, unsigned char* digest)
{
    unsigned char* k_ipad = (unsigned char*)malloc(getBValue());
    unsigned char* k_opad = (unsigned char*)malloc(getBValue());
    unsigned char* tk = (unsigned char*)malloc(getDigestLen());
    unsigned int i;
    if (key_len > getBValue())
    {
        Init();
        Update(key, key_len);
        Final(tk);

        key = tk;
        key_len = getDigestLen();
    }

    /*
     * the HMAC_MD5 transform looks like:
     *
     * MD5(K XOR opad, MD5(K XOR ipad, text))
     *
     * where K is an n byte key
     * ipad is the byte 0x36 repeated 64 times

     * opad is the byte 0x5c repeated 64 times
     * and text is the data being protected
     */
    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);

    /* XOR key (padded to 64 bytes) with ipad and opad values */
    for (i = 0; i < getBValue(); i++)
    {
        k_ipad[i] = k_ipad[i] ^ 0x36;
        k_opad[i] = k_opad[i] ^ 0x5c;
    }
    Init();                  /* init context for 1st
                                              * pass */
    Update(k_ipad, getBValue());     /* start with inner pad */
    Update(text, text_len); /* then text of datagram */
    Final(digest);          /* finish up 1st pass */
    /*
     * perform outer MD5
     */
    Init();                   /* init context for 2nd
                                              * pass */
    Update(k_opad, getBValue());     /* start with outer pad */
    Update(digest, getDigestLen());     /* then results of 1st
                                              * hash */
    Final(digest);          /* finish up 2nd pass */
}

void MD5_Digest::Init()
{
    MD5Init(&context);
}

void MD5_Digest::Update(unsigned char* d, int n)
{
    MD5Update(&context, d, n);
}

void MD5_Digest::Final(unsigned char* o)
{
    MD5Final(o, &context);
}

void SHA256_Digest::Init()
{
    SHA256_Init(&context);
}

void SHA256_Digest::Update(unsigned char* d, int n)
{
    SHA256_Update(&context, d,  n);
}

void SHA256_Digest::Final(unsigned char* o)
{
    SHA256_Final(o, &context);
}

void SHA512_256_Digest::Init()
{
    SHA512_Init(&context);
}

void SHA512_256_Digest::Update(unsigned char* d, int n)
{
    SHA512_Update(&context, d,  n);
}

void SHA512_256_Digest::Final(unsigned char* o)
{
    SHA512_Final(o, &context);
}
