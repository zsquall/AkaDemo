#include "auth.hpp"
#include "debug.hpp"

Auth::Auth(char* al)
{
    if(strcasecmp(al, "AKAv2-md5") == 0)
    {
        digestMethod = new MD5_Digest();
        akaVersion = 2;
    }
    else if(strcasecmp(al, "AKAv1-md5") == 0)
    {
        digestMethod = new MD5_Digest();
        akaVersion = 1;
    }
    else if(strcasecmp(al, "AKAv2-sha-256") == 0)
    {
        digestMethod = new SHA256_Digest();
        akaVersion = 2;
    }
    else if(strcasecmp(al, "AKAv1-sha-256") == 0)
    {
        digestMethod = new SHA256_Digest();
        akaVersion = 1;
    }
    else
    {
        printf("!!!!!not support \r\n");
    }

}
int Auth::calculatePwForAka(unsigned char* pw)
{
    unsigned char nonce_decode[100] = "";
    unsigned char sharekey_bin[16] = "";
    memset(sharekey_bin, 0 , sizeof(char)*16);
    int nonce_len = base64_decode(nonce, nonce_decode);
    int len = hexStrToBin(sharekey, sharekey_bin);

    unsigned char rnd[16];
    unsigned char sqnAk[6];
    unsigned char sqn[6];
    unsigned char ak[6];
    unsigned char ik[16];
    unsigned char ck[16];
    unsigned char amf[2];
    unsigned char mac[8];
    unsigned char res[8];
    unsigned char xmac[8];

    memcpy(rnd, nonce_decode, 16);
    memcpy(sqnAk, nonce_decode+16, 6);
    memcpy(amf, nonce_decode+22, 2);
    memcpy(mac, nonce_decode+24, 8);

    f2345((unsigned char*)sharekey_bin, (unsigned char*)rnd, (unsigned char*)res, (unsigned char*)ck, (unsigned char*)ik, (unsigned char*)ak);

    printBin("sharekey_bin", (unsigned char*)sharekey_bin, 16);
    printBin("rnd", rnd, 16);
    printBin("res", res, 8);
    printBin("ik", ik, 16);
    printBin("ck", ck, 16);
    for(int i =0 ; i < 6; i++)
    {
        sqn[i] = sqnAk[i] ^ ak[i];
    }
    f1((unsigned char*)sharekey_bin, (unsigned char*)rnd, (unsigned char*)sqn, (unsigned char*)amf, (unsigned char*)xmac);
    printBin("xmac", xmac, 8);
    printBin("mac", mac, 8);

    unsigned char resIkCk[40];
    memcpy(resIkCk, res, 8);
    memcpy(resIkCk+8, ik, 16);
    memcpy(resIkCk+24, ck, 16);
    printBin("res+ik+ck", resIkCk, 40);
    unsigned char data[] = "http-digest-akav2-password";
    unsigned char digest[64];
    int digest_len = digestMethod->getDigestLen();
    digestMethod->Hmac(data, (int)strlen((const char*)data), resIkCk, (int)40, digest);
    //digestMethod->Hmac( resIkCk, (int)40, data, (int)strlen((const char*)data),digest);
    printBin("digest", digest, digest_len);
    unsigned char digest_base64[120];
    base64_encode(digest, digest_len, digest_base64);
    printf("digest_base64: %s\r\n", digest_base64);
    if(akaVersion == 1)
    {
        memcpy(pw, res, 8);
        return 8;
    }
    else
    {
        memcpy(pw, digest_base64, strlen((char*)digest_base64));
        return strlen((char*)digest_base64);
    }
}

int Auth::calculateRespBin(unsigned char* response_bin)
{
    unsigned char pw[100];
    int pw_len = calculatePwForAka(pw);
    pw[pw_len] = '\0';

    unsigned char ha1[64];
    int ha1_len = digestMethod->getDigestLen();
    
    digestMethod->Init();
    digestMethod->Update(usr_name, strlen((char*)usr_name));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(realm, strlen((char*)realm));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(pw, pw_len);
    digestMethod->Final(ha1);
    printBin("ha1", ha1, ha1_len);
    unsigned char hexHa1[129];
    binToHex(ha1, ha1_len, hexHa1);

    unsigned char ha2[64];
    int ha2_len = digestMethod->getDigestLen();

    digestMethod->Init();
    digestMethod->Update(method, strlen((char*)method));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(uri, strlen((char*)uri));
    digestMethod->Final(ha2);
    printBin("ha2", ha2, ha2_len);
    unsigned char hexHa2[129];
    binToHex(ha2, ha2_len, hexHa2);

    digestMethod->Init();
    digestMethod->Update(hexHa1, strlen((char*)hexHa1));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(nonce, strlen((char*)nonce));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(nc, strlen((char*)nc));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(cnonce, strlen((char*)cnonce));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(qop, strlen((char*)qop));
    digestMethod->Update((unsigned char*)":", 1);
    digestMethod->Update(hexHa2, strlen((char*)hexHa2));
    digestMethod->Final(response_bin);
    printBin("response_bin", response_bin, digestMethod->getDigestLen());

    return digestMethod->getDigestLen();
}

