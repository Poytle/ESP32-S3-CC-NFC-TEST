#pragma once
#include <Arduino.h>
#include <Wire.h>
#include <cstdio>
// PN532 I2C status polling: IRQ and reset wires are not required.
class PN532 {
  const char *error_ = "none";
  char detail_[160] = {};
  int exchangeStatus_ = -1;
  const char *phase_ = "idle";
  size_t readRequested_ = 0, readReceived_ = 0;
  bool fail(const char *message) { error_ = message; Serial.printf("PN532: %s\n", message); return false; }
  bool readRaw(uint8_t *out, size_t length) {
    // Two-argument overloads in Arduino-ESP32 2.x return uint8_t: 270 becomes 14.
    // Force the size_t overload for both the requested length and returned count.
    readRequested_=length;
    readReceived_=Wire.requestFrom(static_cast<uint16_t>(0x24),length,true);
    if (readReceived_ != length) {
      while (Wire.available()) Wire.read();
      return false;
    }
    for (size_t i=0; i<length; i++) out[i]=Wire.read();
    return true;
  }
  bool readBytes(uint8_t *out,size_t length){
    if(readRaw(out,length))return true;
    snprintf(detail_,sizeof(detail_),"I2C read failed: requested %u bytes, received %u",unsigned(length),unsigned(readReceived_));
    return fail(detail_);
  }
  bool ready(uint32_t timeout) {
    uint32_t start=millis();unsigned failures=0;
    do { uint8_t status;
      // PN532 may briefly NACK its address after a preceding exchange (UM0701-02 6.2.4).
      if (!readRaw(&status,1)) {
        if(++failures>=3)return fail("I2C read failed during ready polling after 3 attempts");
      }else{failures=0;if(status&1)return true;}
      delay(5);
    } while (millis()-start<timeout);
    return fail("Timed out waiting for PN532 ready");
  }
  bool repeatResponse(uint32_t timeout){
    const uint8_t nack[]={0,0,255,255,0,0};
    Wire.beginTransmission(0x24);Wire.write(nack,sizeof(nack));
    if(Wire.endTransmission()!=0)return fail("I2C response retransmission request failed");
    delay(5);return ready(timeout);
  }
public:
  const char *lastError() const { return error_; }
  const char *phase() const { return phase_; }
  int exchangeStatus() const { return exchangeStatus_; }
  size_t readRequested() const { return readRequested_; }
  size_t readReceived() const { return readReceived_; }
  bool command(const uint8_t *cmd, size_t len, uint8_t *out, size_t &outLen, uint32_t timeout=1000) {
    error_="none";
    if (!len || len>260) return fail("Command too large");
    uint8_t frame[272]={0,0,255}; size_t p=3, n=len+1;
    if(n<255){frame[p++]=n;frame[p++]=uint8_t(-n);}
    else {frame[p++]=255;frame[p++]=255;frame[p++]=n>>8;frame[p++]=n;frame[p++]=uint8_t(-((n>>8)+(n&255)));}
    frame[p++]=0xd4; uint8_t sum=0xd4;
    for(size_t i=0;i<len;i++){frame[p++]=cmd[i];sum+=cmd[i];}
    frame[p++]=uint8_t(-sum);frame[p++]=0;
    phase_="command write";
    Wire.beginTransmission(0x24);Wire.write(frame,p);
    if(Wire.endTransmission()!=0)return fail("I2C command write failed");
    delay(2);
    phase_="ACK ready";if(!ready(timeout))return false;
    phase_="ACK read";uint8_t ack[7]; if(!readBytes(ack,sizeof(ack)))return false;
    const uint8_t expected[]={1,0,0,255,0,255,0};
    if(!(ack[0]&1) || memcmp(ack+1,expected+1,6))return fail("Invalid PN532 ACK");
    phase_="response ready";if(!ready(timeout))return false;
    // Inspect the header, then request retransmission with the PN532 NACK frame.
    // This avoids clocking 540 bytes for every response, including 10-byte ones.
    uint8_t response[540];
    phase_="response header";
    if(!readBytes(response,9)){
      if(!repeatResponse(timeout) || !readBytes(response,9))return false;
    }
    if(!(response[0]&1) || response[1]!=0 || response[2]!=0 || response[3]!=255)
      return fail("Invalid response preamble");
    size_t at=6, count=response[4];
    if(count==255 && response[5]==255){
      if(uint8_t(response[6]+response[7]+response[8]))return fail("Invalid extended length checksum");
      count=(response[6]<<8)|response[7];at=9;
    } else if(uint8_t(response[4]+response[5]))return fail("Invalid length checksum");
    uint8_t header[8]; memcpy(header,response+1,at-1);
    size_t got=at+count+2;
    if(count<2 || got>sizeof(response) || count-2>outLen)return fail("Response exceeds buffer");
    bool received=false;phase_="response frame";
    for(unsigned attempt=0;attempt<2;attempt++){
      if(!repeatResponse(timeout))return false;
      if(readBytes(response,got)){received=true;break;}
    }
    if(!received)return false;
    if(!(response[0]&1) || memcmp(response+1,header,at-1))
      return fail("Invalid retransmitted response");
    if(count<2 || at+count+2>got || response[at]!=0xd5 || response[at+1]!=uint8_t(cmd[0]+1))return fail("Unexpected PN532 response command");
    sum=0;for(size_t i=0;i<=count;i++)sum+=response[at+i];
    if(sum || response[at+count+1]!=0 || count-2>outLen)return fail("Invalid response checksum or postamble");
    outLen=count-2;memcpy(out,response+at+2,outLen);error_="none";return true;
  }
  bool begin(){
    delay(100); // Allow module power-up and oscillator startup.
    Wire.beginTransmission(0x24);
    if(Wire.endTransmission()!=0)return fail("No device ACK at I2C 0x24: check wiring and PN532 mode switches, then power-cycle");
    uint8_t out[24];size_t n=sizeof(out);uint8_t fw[]={2};
    if(!command(fw,1,out,n) || n!=4 || out[0]!=0x32)return false;
    uint8_t sam[]={0x14,1,0x14,0};n=sizeof(out);if(!command(sam,4,out,n))return false;
    uint8_t retries[]={0x32,5,0xff,1,1};n=sizeof(out);return command(retries,5,out,n);
  }
  bool poll(uint8_t *uid, size_t &length){uint8_t cmd[]={0x4a,1,0};uint8_t out[64];size_t n=64;
    if(!command(cmd,3,out,n,1000) || n<6 || out[0]!=1)return false;
    size_t k=out[5];if(k>10 || k>length || 6+k>n)return false;
    memcpy(uid,out+6,k);length=k;return true;
  }
  bool exchange(const uint8_t *apdu,size_t len,uint8_t *out,size_t &n){
    exchangeStatus_=-1;
    if(len>258)return fail("APDU exceeds supported command length");
    uint8_t cmd[260], response[520];
    cmd[0]=0x40;cmd[1]=1;memcpy(cmd+2,apdu,len);
    size_t commandSize=len+2, used=0, capacity=n;
    // MI (bit 6) requests continuation. Only the low six bits are error codes.
    // Continuations fetch remaining bytes; they never repeat the original APDU.
    for(unsigned fragment=0;fragment<8;fragment++){
      size_t k=sizeof(response);
      if(!command(cmd,commandSize,response,k,3000))return false;
      if(k<1)return fail("PN532 exchange response missing status byte");
      uint8_t status=response[0];exchangeStatus_=status;
      uint8_t code=status&0x3f;
      if(code){
        const char *reason="RF/target error";
        switch(code){
          case 0x01:reason="target timeout (card did not answer)";break;
          case 0x02:reason="RF CRC error";break;
          case 0x03:reason="RF parity error";break;
          case 0x07:reason="PN532 communication buffer insufficient";break;
          case 0x09:reason="PN532 RF buffer overflow";break;
          case 0x0b:reason="RF protocol error";break;
          case 0x0e:reason="PN532 internal buffer overflow";break;
          case 0x10:reason="invalid PN532 parameter";break;
          case 0x25:reason="invalid target state";break;
          case 0x2b:reason="card disappeared";break;
          case 0x26:reason="operation not allowed";break;
          case 0x27:reason="unknown target";break;
          case 0x29:reason="target released";break;
        }
        snprintf(detail_,sizeof(detail_),"PN532 status 0x%02X: %s",status,reason);return fail(detail_);
      }
      size_t start=(status&0x80)?2:1; // Optional node address is transport metadata.
      if(k<start)return fail("PN532 NAD flag without node address");
      if(k-start>capacity-used)return fail("Chained card response exceeds APDU buffer");
      memcpy(out+used,response+start,k-start);used+=k-start;
      if(!(status&0x40)){n=used;return true;}
      commandSize=2; // InDataExchange(Tg=1), no outgoing APDU data.
    }
    return fail("PN532 chained response exceeded 8 fragments");
  }
};
