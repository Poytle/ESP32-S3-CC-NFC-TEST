#include "tlv.h"
#include <cassert>
int main(){
 Tlv t;size_t p=0;const uint8_t valid[]={0x9f,0x46,3,1,2,3};
 assert(nextTlv(valid,sizeof(valid),p,t));assert(t.tag==0x9f46 && t.size==3 && p==6);
 const uint8_t truncated[]={0x70,4,1};p=0;assert(!nextTlv(truncated,sizeof(truncated),p,t));
 const uint8_t indefinite[]={0x70,0x80};p=0;assert(!nextTlv(indefinite,sizeof(indefinite),p,t));
 const uint8_t tag[]={0x9f,0x80,0x80,0};p=0;assert(!nextTlv(tag,sizeof(tag),p,t));
 const uint8_t nested[]={0x70,3,0x82,1,0x40};p=0;assert(nextTlv(nested,5,p,t) && t.constructed);size_t q=0;Tlv inner;assert(nextTlv(t.data,t.size,q,inner) && inner.tag==0x82);
 const uint8_t longLen[]={0x90,0x81,1,0x42};p=0;assert(nextTlv(longLen,4,p,t) && t.size==1);
}
