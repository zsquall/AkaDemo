#ifndef __AUTH_HPP__
#define __AUTH_HPP__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "digest.hpp"
#include "encrypt/hex.hpp"
#include "encrypt/base64.h"
#include "encrypt/aka.h"

class Auth
{
    private:
        unsigned char* usr_name;
        unsigned char* realm;
        unsigned char* method;
        unsigned char* uri;
        unsigned char* nc;
        unsigned char* cnonce;
        unsigned char* qop;
        unsigned char* nonce;
        unsigned char* sharekey;
        Digest* digestMethod;
        int akaVersion;

        int calculatePwForAka(unsigned char* pw);

    public:
        Auth(char* al);
        void setUsrName(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            usr_name = obj;
        }

        void setRealm(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            realm = obj;
        }

        void setMethod(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            method = obj;
        }

        void setUri(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            uri = obj;
        }

        void setNc(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            nc = obj;
        }

        void setCnonce(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            cnonce = obj;
        }

        void setQop(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            qop = obj;
        }

        void setNonce(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            nonce = obj;
        }

        void setSharedKey_hex(unsigned char* in)
        {
            unsigned char* obj = (unsigned char*)malloc(strlen((char*)in + 1)*sizeof(unsigned char*));
            memcpy(obj, in, strlen((char*)in));
            obj[strlen((char*)in)] = '\0';
            sharekey = obj;
        }

        int calculateRespBin(unsigned char* response_bin);
};
#endif

