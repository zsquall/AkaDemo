#ifndef __DIGEST_HPP__
#define __DIGEST_HPP__

#include "encrypt/md5.h"
#include "encrypt/sha.h"
class Digest
{
    public:

        virtual void Init() = 0;
        virtual void Update(unsigned char* d, int n) = 0;
        virtual void Final(unsigned char* o) = 0;
        void Hmac(unsigned char* data, int data_len, unsigned char* pw, int pw_len, unsigned char* o);
        virtual int getDigestLen() = 0;
        virtual int getBValue() = 0;
};

class MD5_Digest: public Digest
{
    public:
        virtual void Init();
        virtual void Update(unsigned char* d, int n);
        virtual void Final(unsigned char* o);
        int getDigestLen()
        {
            return 16;
        }
        int getBValue()
        {
            return 64;
        }
    private:
        MD5_CTX context;
};

class SHA256_Digest: public Digest
{
    public:
        virtual void Init();
        virtual void Update(unsigned char* d, int n);
        virtual void Final(unsigned char* o);
        int getDigestLen()
        {
            return 32;
        }
        int getBValue()
        {
            return 64;
        }
    private:
        SHA256_CTX context;
};

class SHA512_256_Digest: public Digest
{
    public:
        virtual void Init();
        virtual void Update(unsigned char* d, int n);
        virtual void Final(unsigned char* o);
        int getDigestLen()
        {
            return 64;
        }
        int getBValue()
        {
            return 128;
        }
    private:
        SHA512_CTX context;
};
#endif
