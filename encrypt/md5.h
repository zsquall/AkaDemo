/* MD5.H - header file for MD5C.C
 */

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

#ifndef _MD5_H_
#define _MD5_H_

#ifdef ISAM_7353_2UMDU

/**********************************
    Below marcos are for rename function name xxx to xxx_SIP.
    Since these functions are also defined in MEGO module.
*************************************/
#ifndef RENAME_WITH_SIP
#define RENAME_WITH_SIP(func) func##_SIP
#endif
#define MD5Final RENAME_WITH_SIP(MD5Final)
#define MD5Init RENAME_WITH_SIP(MD5Init)
#define MD5Update RENAME_WITH_SIP(MD5Update)

#endif


#ifndef DOXYGEN

#ifdef __cplusplus
extern "C"
{
#endif

/* modified for oSIP: GCC supports this feature */
#define PROTOTYPES 1

#ifndef PROTOTYPES
#define PROTOTYPES 0
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char*      POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int  UINT2;

/* UINT4 defines a four byte word */
typedef unsigned int        UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif


/**
 * Structure for holding MD5 context.
 * @var MD5_CTX
 */
typedef struct
{
    UINT4           state[4];             /* state (ABCD) */
    UINT4           count[2];             /* number of bits, modulo 2^64 (lsb first) */
    unsigned char   buffer[64];   /* input buffer */
}
MD5_CTX;

void    MD5Init PROTO_LIST((MD5_CTX*));
void    MD5Update PROTO_LIST((MD5_CTX*, unsigned char*, unsigned int));
void    MD5Final PROTO_LIST((unsigned char[16], MD5_CTX*));
void    hmac_md5_digest(unsigned char* text, unsigned int text_len, unsigned char* key, unsigned int key_len, unsigned char* digest);


#ifdef __cplusplus
}
#endif
#endif
#endif
