#ifndef __AKA_H__
#define __AKA_H__
typedef unsigned char   u8;
typedef unsigned int     u32;

void genSQN(u8 oldSQN[6], u8 newSQN[6]);
bool chkSQN(u8 oldSQN[6], u8 newSQN[6]);

void genAV(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2],
           u8 randAutn[32], u8 res[8], u8 ik[16], u8 ck[16]);
void getRandSqnAmf(u8 k[16], u8 randAutn[32], u8 rand[16], u8 sqn[6], u8 amf[2], u8 res[8], u8 ik[16], u8 ck[16]);

void genAuts(u8 k[16], u8 rand[16], u8 ue_sqn[6], u8 amf[2], u8 auts[14]);
void getResyncInputs(u8 k[16], u8 rand_auts[30], u8 sqn_ms[6], u8 rand_usim[16], u8 mac_s_usim[8]);
void f1(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_a[8]);
void f2345(u8 k[16], u8 rand[16], u8 res[8], u8 ck[16], u8 ik[16], u8 ak[6]);
void f1star(u8 k[16], u8 rand[16], u8 sqn[6], u8 amf[2], u8 mac_s[8]);
void f5star(u8 k[16], u8 rand[16], u8 ak[6]);
void ComputeOPc(u8 op_c[16]);

void RijndaelKeySchedule(u8 key[16]);
void RijndaelEncrypt(u8 in[16], u8 out[16]);

#endif

