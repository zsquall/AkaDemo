#ifndef __BASE_64_H__
#define __BASE_64_H__

void base64_encode(unsigned char* in_buf, int in_len, unsigned char* out_buf);
int base64_decode(unsigned char* source, unsigned char* out_buf);

#endif
