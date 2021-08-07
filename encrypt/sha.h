#ifndef __SHA_EXT_H__
#define __SHA_EXT_H__
#ifdef  __cplusplus
extern "C" {
#endif
# define SHA_LONG unsigned long
# define SHA_LBLOCK      16
# define SHA512_CBLOCK   (SHA_LBLOCK*8)
# define SHA256_CBLOCK   (SHA_LBLOCK*4)/* SHA-256 treats input data as a
                                        * contiguous array of 32 bit wide
                                        * big-endian values. */
# define SHA_CBLOCK      (SHA_LBLOCK*4)

# define SHA224_DIGEST_LENGTH    28
# define SHA256_DIGEST_LENGTH    32
# define SHA384_DIGEST_LENGTH    48
# define SHA512_DIGEST_LENGTH    64

#define fips_md_init(alg) fips_md_init_ctx(alg, alg)
#define fips_md_init_ctx(alg, cx) \
    int alg##_Init(cx##_CTX *c)

#   define SHA_LONG64 unsigned long long
#   define U64(C)     C##ULL

typedef unsigned long int    Ip_size_t;
typedef unsigned long int    size_t;

typedef struct SHAstate_st
{
    SHA_LONG h0, h1, h2, h3, h4;
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num;
} SHA_CTX;

typedef struct SHA256state_st
{
    SHA_LONG h[8];
    SHA_LONG Nl, Nh;
    SHA_LONG data[SHA_LBLOCK];
    unsigned int num, md_len;
} SHA256_CTX;

typedef struct SHA512state_st
{
    SHA_LONG64 h[8];
    SHA_LONG64 Nl, Nh;
    union
    {
        SHA_LONG64 d[SHA_LBLOCK];
        unsigned char p[SHA512_CBLOCK];
    } u;
    unsigned int num, md_len;
} SHA512_CTX;

# define AES_MAXNR 14

int SHA256_Init(SHA256_CTX* c);
int SHA256_Update(SHA256_CTX* c, const void* data, Ip_size_t len);
int SHA256_Final(unsigned char* md, SHA256_CTX* c);
unsigned char* SHA256(const unsigned char* d, size_t n, unsigned char* md);

int SHA512_Init(SHA512_CTX* c);
int SHA512_256_Init(SHA512_CTX* c);
int SHA512_Update(SHA512_CTX* c, const void* data, size_t len);
int SHA512_Final(unsigned char* md, SHA512_CTX* c);

void OPENSSL_cleanse(void* ptr, size_t len);
#ifdef  __cplusplus
}
#endif
#endif
