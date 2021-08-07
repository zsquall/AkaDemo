#include <stdio.h>
#include <string.h>
#include "auth.hpp"
#include "digest.hpp"
#include "encrypt/sha.h"

void printBin(const char* tag, unsigned char* buf, int len)
{
    printf("%s:", tag);
    int i = 0;
    for(i = 0; i < len; i++)
    {
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\r\n");
}

extern "C"
int runAKA(unsigned char* usr_name,
        unsigned char* realm,
        unsigned char* method,
        unsigned char* uri,
        unsigned char* nc,
        unsigned char* cnonce,
        unsigned char* qop,
        unsigned char* nonce,
        unsigned char* sharekey,
        unsigned char* al,
        unsigned char* res)
{
    Auth* authtication = new Auth((char*)al);
    authtication->setUsrName(usr_name);
    authtication->setRealm(realm);
    authtication->setMethod(method);
    authtication->setUri(uri);
    authtication->setNc(nc);
    authtication->setCnonce(cnonce);
    authtication->setQop(qop);
    authtication->setNonce(nonce);
    authtication->setSharedKey_hex(sharekey);
    unsigned char resBin[100];
    int resLen = authtication->calculateRespBin(resBin);
    binToHex(resBin, resLen, res);
    return 0;
}

int main()
{
    /*usr_name : 13288615559
     * realm    : qd.lucentlab.com
     * method   : REGISTER
     * uri      : sip:135.252.37.124
     * nc       : 00000001
     * cnonce   : 164-19fd-3b18380
     * qop      : auth
     * nonce    : wRRaR8EUWkfBFFpHP6G0Y4R/UXFEebm5GJTRVFk6rD4=
     * sharekey : 465b5ce8b199b49faa5f0a2ee238a6bc
     */
    unsigned char res[100];
    runAKA((unsigned char*)"13288615559", (unsigned char*)"qd.lucentlab.com", (unsigned char*)"REGISTER", (unsigned char*)"sip:135.252.37.124", 
           (unsigned char*)"00000001", (unsigned char*)"164-19fd-3b18380", (unsigned char*)"auth", (unsigned char*)"wRRaR8EUWkfBFFpHP6G0Y4R", 
          (unsigned char*)"465b5ce8b199b49faa5f0a2ee238a6bc", (unsigned char*)"AKAv2-SHA-256", res); 

    printBin("res", res, 100);
            

}
