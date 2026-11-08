#pragma once
#include <Arduino.h>
#include <Wire.h>
// PN532 I2C status polling: IRQ and reset wires are not required.
class PN532 {
  bool ready(uint32_t timeout) {
    uint32_t start=millis();
    do { if (Wire.requestFrom(0x24,1)==1 && (Wire.read()&1)) return true; delay(2); }
    while (millis()-start<timeout); return false;
  }
public:
  bool command(const uint8_t *cmd, size_t len, uint8_t *out, size_t &outLen, uint32_t timeout=1000) {
    if (!len || len>260) return false;
    uint8_t frame[272]={0,0,255}; size_t p=3, n=len+1;
    if(n<255){frame[p++]=n;frame[p++]=uint8_t(-n);}
    else {frame[p++]=255;frame[p++]=255;frame[p++]=n>>8;frame[p++]=n;frame[p++]=uint8_t(-((n>>8)+(n&255)));}
    frame[p++]=0xd4; uint8_t sum=0xd4;
    for(size_t i=0;i<len;i++){frame[p++]=cmd[i];sum+=cmd[i];}
    frame[p++]=uint8_t(-sum);frame[p++]=0;
    Wire.beginTransmission(0x24);Wire.write(frame,p);
    if(Wire.endTransmission()!=0 || !ready(timeout))return false;
    uint8_t ack[7]; if(Wire.requestFrom(0x24,7)!=7)return false;
    for(auto &b:ack)b=Wire.read();
    const uint8_t expected[]={1,0,0,255,0,255,0};
    if(memcmp(ack,expected,7) || !ready(timeout))return false;
    // One complete I2C read; ESP32 Wire buffer is enlarged in setup.
    uint8_t response[540]; size_t got=Wire.requestFrom(0x24,540);
    for(size_t i=0;i<got;i++)response[i]=Wire.read();
    if(got<9 || response[0]!=1 || response[1]!=0 || response[2]!=0 || response[3]!=255)return false;
    size_t at=6, count=response[4];
    if(count==255 && response[5]==255){
      if(got<12 || uint8_t(response[6]+response[7]+response[8]))return false;
      count=(response[6]<<8)|response[7];at=9;
    } else if(uint8_t(response[4]+response[5]))return false;
    if(count<2 || at+count+2>got || response[at]!=0xd5 || response[at+1]!=uint8_t(cmd[0]+1))return false;
    sum=0;for(size_t i=0;i<=count;i++)sum+=response[at+i];
    if(sum || response[at+count+1]!=0 || count-2>outLen)return false;
    outLen=count-2;memcpy(out,response+at+2,outLen);return true;
  }
  bool begin(){uint8_t out[24];size_t n=sizeof(out);uint8_t fw[]={2};
    if(!command(fw,1,out,n) || n!=4 || out[0]!=0x32)return false;
    uint8_t sam[]={0x14,1,0x14,0};n=sizeof(out);if(!command(sam,4,out,n))return false;
    uint8_t retries[]={0x32,5,0xff,1,1};n=sizeof(out);return command(retries,5,out,n);
  }
  bool poll(uint8_t *uid, size_t &length){uint8_t cmd[]={0x4a,1,0};uint8_t out[64];size_t n=64;
    if(!command(cmd,3,out,n,400) || n<6 || out[0]!=1)return false;
    size_t k=out[5];if(k>10 || k>length || 6+k>n)return false;
    memcpy(uid,out+6,k);length=k;return true;
  }
  bool exchange(const uint8_t *apdu,size_t len,uint8_t *out,size_t &n){
    uint8_t cmd[262], response[520];if(len>259)return false;
    cmd[0]=0x40;cmd[1]=1;memcpy(cmd+2,apdu,len);size_t k=sizeof(response);
    if(!command(cmd,len+2,response,k) || k<1 || response[0]!=0 || k-1>n)return false;
    n=k-1;memcpy(out,response+1,n);return true;
  }
};
