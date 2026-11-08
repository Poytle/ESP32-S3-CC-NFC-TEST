#pragma once
#include <stdint.h>
#include <stddef.h>
// PAN BCD can end in F padding. Track 2 starts with PAN and a D separator.
inline bool decodePan(const uint8_t *data,size_t length,bool track,char *out,size_t capacity){
 size_t used=0;bool ended=false;
 for(size_t i=0;i<length*2;i++){
  uint8_t digit=(i&1)?data[i/2]&15:data[i/2]>>4;
  if(track && digit==13){ended=true;break;}
  if(!track && digit==15){for(size_t j=i;j<length*2;j++)if(((j&1)?data[j/2]&15:data[j/2]>>4)!=15)return false;ended=true;break;}
  if(digit>9 || used+1>=capacity)return false;
  out[used++]=char('0'+digit);
 }
 out[used]=0;return used>=8 && used<=19 && (!track || ended);
}
// DDA needs a four-byte unpredictable number. Don't guess unknown DDOL inputs.
inline bool ddaInput(const uint8_t *ddol,size_t size,const uint8_t nonce[4],uint8_t *out,size_t &length){
 if(size!=3 || ddol[0]!=0x9f || ddol[1]!=0x37 || ddol[2]!=4 || length<4)return false;
 for(size_t i=0;i<4;i++)out[i]=nonce[i];length=4;return true;
}
