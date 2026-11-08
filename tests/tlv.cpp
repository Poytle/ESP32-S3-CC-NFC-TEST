#include "tlv.h"
#include "emv_data.h"
#include <cstring>
#include <cassert>
int main(){
 char pan[20];const uint8_t panBytes[]={0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x5f};
 assert(decodePan(panBytes,sizeof(panBytes),false,pan,sizeof(pan)));assert(!std::strcmp(pan,"123456789012345"));
 const uint8_t track[]={0x12,0x34,0x56,0x78,0x90,0x12,0x34,0x56,0xd2,0x70,0x11};
 assert(decodePan(track,sizeof(track),true,pan,sizeof(pan)));assert(!std::strcmp(pan,"1234567890123456"));
 const uint8_t badPan[]={0x12,0x34,0x56,0x7a};assert(!decodePan(badPan,sizeof(badPan),false,pan,sizeof(pan)));
 const uint8_t ddol[]={0x9f,0x37,4},nonce[]={1,2,3,4},unsupported[]={0x9f,0x02,6};uint8_t input[4];size_t length=4;
 assert(ddaInput(ddol,3,nonce,input,length));assert(length==4 && !std::memcmp(input,nonce,4));
 assert(!ddaInput(unsupported,3,nonce,input,length));assert(!ddaInput(ddol,2,nonce,input,length));

 Tlv t;size_t p=0;const uint8_t valid[]={0x9f,0x46,3,1,2,3};
 assert(nextTlv(valid,sizeof(valid),p,t));assert(t.tag==0x9f46 && t.size==3 && p==6);
 const uint8_t truncated[]={0x70,4,1};p=0;assert(!nextTlv(truncated,sizeof(truncated),p,t));
 const uint8_t indefinite[]={0x70,0x80};p=0;assert(!nextTlv(indefinite,sizeof(indefinite),p,t));
 const uint8_t tag[]={0x9f,0x80,0x80,0};p=0;assert(!nextTlv(tag,sizeof(tag),p,t));
 const uint8_t nested[]={0x70,3,0x82,1,0x40};p=0;assert(nextTlv(nested,5,p,t) && t.constructed);size_t q=0;Tlv inner;assert(nextTlv(t.data,t.size,q,inner) && inner.tag==0x82);
 const uint8_t longLen[]={0x90,0x81,1,0x42};p=0;assert(nextTlv(longLen,4,p,t) && t.size==1);
}
