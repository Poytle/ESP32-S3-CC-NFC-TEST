#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ArduinoJson.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include "pn532.h"
#include "tlv.h"
#include "web_generated.h"
WebServer server(80); PN532 reader; bool nfcReady=false, scanRequested=false;
JsonDocument state; String apPassword;
mbedtls_ecdsa_context rootKey, issuerKey, cardKey;
bool cryptoReady=false;
int rng(void *, unsigned char *out,size_t n){esp_fill_random(out,n);return 0;}
String hex(const uint8_t *b,size_t n){static const char h[]="0123456789ABCDEF";String s;s.reserve(n*2);while(n--){s+=h[*b>>4];s+=h[*b++&15];}return s;}
void sendJson(JsonDocument &doc){String s;serializeJson(doc,s);server.sendHeader("Cache-Control","no-store");server.send(200,"application/json",s);}
void inspect(const uint8_t *data,size_t size,unsigned depth=0){
 if(depth>8)return; size_t pos=0;Tlv t;
 while(nextTlv(data,size,pos,t)){
  if(t.constructed){inspect(t.data,t.size,depth+1);continue;}
  if(t.tag==0x4f && !state["aid"].is<String>())state["aid"]=hex(t.data,t.size);
  if(t.tag==0x50 || t.tag==0x9f12){String label;for(size_t i=0;i<t.size;i++)label+=t.data[i]>=32 && t.data[i]<127?char(t.data[i]):'?';state["application"]=label;}
  if(t.tag==0x5a || t.tag==0x57){String pan=hex(t.data,t.size);int end=pan.indexOf('D');if(end>=0)pan=pan.substring(0,end);while(pan.endsWith("F"))pan.remove(pan.length()-1);if(pan.length()>=4)state["pan"]=String("•••• ")+pan.substring(pan.length()-4);}
  if(t.tag==0x82)state["aip"]=hex(t.data,t.size);
  if(t.tag==0x8f)state["caIndex"]=hex(t.data,t.size);
  if(t.tag==0x90 || t.tag==0x9f46 || t.tag==0x9f4b){String key=t.tag==0x90?"issuerCertificate":t.tag==0x9f46?"cardCertificate":"dynamicSignature";state[key]=hex(t.data,t.size);}
 }
}
bool findTag(const uint8_t *b,size_t n,uint32_t tag,Tlv &result,unsigned depth=0){if(depth>8)return false;size_t p=0;Tlv t;while(nextTlv(b,n,p,t)){if(t.tag==tag){result=t;return true;}if(t.constructed && findTag(t.data,t.size,tag,result,depth+1))return true;}return false;}
uint8_t response[520];size_t responseSize;
bool apdu(const char *name,const uint8_t *cmd,size_t n){
 responseSize=sizeof(response);JsonObject log=state["steps"].as<JsonArray>().add<JsonObject>();log["command"]=name;
 if(!reader.exchange(cmd,n,response,responseSize) || responseSize<2){log["status"]="Transport failed";return false;}
 uint16_t sw=(response[responseSize-2]<<8)|response[responseSize-1];responseSize-=2;uint8_t swBytes[]={uint8_t(sw>>8),uint8_t(sw)};log["status"]=hex(swBytes,2);
 if(sw!=0x9000)return false;inspect(response,responseSize);return true;
}
void scan(){
 state.clear();state["steps"].to<JsonArray>();state["verification"]="Not authenticated — no EMV trust chain verification performed";
 uint8_t uid[10];size_t uidSize=10;
 if(!reader.poll(uid,uidSize)){state["status"]="No ISO14443A card found. Hold card steady and scan again.";return;}
 state["uid"]=hex(uid,uidSize);state["status"]="Card detected";
 uint8_t selectPpse[]={0,0xa4,4,0,14,'2','P','A','Y','.','S','Y','S','.','D','D','F','0','1',0};
 if(!apdu("SELECT PPSE",selectPpse,sizeof(selectPpse))){state["status"]="Card found; payment directory unavailable";return;}
 Tlv aid;if(!findTag(response,responseSize,0x4f,aid) || aid.size<5 || aid.size>16){state["status"]="No supported payment application in PPSE";return;}
 uint8_t select[22]={0,0xa4,4,0,uint8_t(aid.size)};memcpy(select+5,aid.data,aid.size);select[5+aid.size]=0;
 if(!apdu("SELECT payment application",select,aid.size+6))return;
 // Fill PDOL using neutral terminal values and a fresh unpredictable number.
 uint8_t gpo[255]={0x80,0xa8,0,0,0,0x83,0};size_t total=0;Tlv pdol;
 uint8_t nonce[4];esp_fill_random(nonce,4);state["challenge"]=hex(nonce,4);
 if(findTag(response,responseSize,0x9f38,pdol)){
  size_t p=0;while(p<pdol.size){uint32_t tag=pdol.data[p++];if((tag&31)==31){if(p>=pdol.size)return;uint8_t b=pdol.data[p++];tag=(tag<<8)|b;if(b&128){state["status"]="Unsupported PDOL tag";return;}}
   if(p>=pdol.size)return;size_t len=pdol.data[p++];if(total+len>120){state["status"]="PDOL too large";return;}
   memset(gpo+7+total,0,len);
   if(tag==0x9f37 && len==4)memcpy(gpo+7+total,nonce,4);
   if(tag==0x9f66 && len==4){gpo[7+total]=0x26;gpo[8+total]=0;}
   if((tag==0x9f1a || tag==0x5f2a) && len==2){gpo[7+total]=0x03;gpo[8+total]=0x56;}
   total+=len;
  }
 }
 gpo[4]=total+2;gpo[6]=total;gpo[7+total]=0;
 if(!apdu("GET PROCESSING OPTIONS (zero amount)",gpo,total+8)){state["status"]="Card declined inspection GPO";return;}
 uint8_t afl[252];size_t aflSize=0;Tlv t;
 if(findTag(response,responseSize,0x94,t)){aflSize=t.size;if(aflSize<=sizeof(afl))memcpy(afl,t.data,aflSize);else return;}
 else if(findTag(response,responseSize,0x80,t) && t.size>=2){state["aip"]=hex(t.data,2);aflSize=t.size-2;if(aflSize>sizeof(afl))return;memcpy(afl,t.data+2,aflSize);}
 if(aflSize%4){state["status"]="Malformed AFL";return;}
 unsigned records=0;
 for(size_t i=0;i<aflSize;i+=4){uint8_t sfi=afl[i]>>3,first=afl[i+1],last=afl[i+2];if(sfi<1 || sfi>30 || !first || first>last || last>32)continue;
  for(unsigned rec=first;rec<=last && records<32;rec++,records++){uint8_t cmd[]={0,0xb2,uint8_t(rec),uint8_t((sfi<<3)|4),0};apdu("READ RECORD",cmd,5);}
 }
 state["status"]="Inspection complete";
}
void digest(const uint8_t *b,size_t n,uint8_t *out){mbedtls_sha256_ret(b,n,out,0);}
size_t publicBytes(mbedtls_ecdsa_context &key,uint8_t *out){size_t n=0;mbedtls_ecp_point_write_binary(&key.grp,&key.Q,MBEDTLS_ECP_PF_UNCOMPRESSED,&n,out,100);return n;}
bool sign(mbedtls_ecdsa_context &key,const uint8_t *hash,uint8_t *sig,size_t &n){return mbedtls_ecdsa_write_signature(&key,MBEDTLS_MD_SHA256,hash,32,sig,&n,rng,nullptr)==0;}
void demo(){
 JsonDocument doc;if(!cryptoReady){server.send(503,"text/plain","Crypto initialization failed");return;}
 uint8_t issuerPub[100],cardPub[100],rootPub[100],cert1[100],cert2[100],sig[100],hash[32],challenge[32];size_t n1=0,n2=0,ns=0;
 size_t ip=publicBytes(issuerKey,issuerPub),cp=publicBytes(cardKey,cardPub),rp=publicBytes(rootKey,rootPub);
 digest(issuerPub,ip,hash);bool c1=sign(rootKey,hash,cert1,n1) && mbedtls_ecdsa_read_signature(&rootKey,hash,32,cert1,n1)==0;
 digest(cardPub,cp,hash);bool c2=sign(issuerKey,hash,cert2,n2) && mbedtls_ecdsa_read_signature(&issuerKey,hash,32,cert2,n2)==0;
 esp_fill_random(challenge,32);digest(challenge,32,hash);bool signedOk=sign(cardKey,hash,sig,ns);
 bool valid=signedOk && mbedtls_ecdsa_read_signature(&cardKey,hash,32,sig,ns)==0;
 challenge[0]^=1;digest(challenge,32,hash);bool tampered=signedOk && mbedtls_ecdsa_read_signature(&cardKey,hash,32,sig,ns)!=0;challenge[0]^=1;
 uint8_t fresh[32];esp_fill_random(fresh,32);digest(fresh,32,hash);bool replay=signedOk && mbedtls_ecdsa_read_signature(&cardKey,hash,32,sig,ns)!=0;
 doc["mode"]="Synthetic ECDSA P-256 PKI demo, executed on ESP32. Not a payment-card signature or EMV certificate format.";
 doc["rootPublicKey"]=hex(rootPub,rp);doc["issuerPublicKey"]=hex(issuerPub,ip);doc["cardPublicKey"]=hex(cardPub,cp);
 doc["issuerCertificateSignature"]=hex(cert1,n1);doc["cardCertificateSignature"]=hex(cert2,n2);doc["challenge"]=hex(challenge,32);doc["signature"]=hex(sig,ns);
 doc["rootToIssuerValid"]=c1;doc["issuerToCardValid"]=c2;doc["signatureValid"]=valid;doc["tamperedChallengeRejected"]=tampered;doc["replayWithFreshChallengeRejected"]=replay;sendJson(doc);
}
void setup(){
 Serial.begin(115200);Wire.setBufferSize(1024);Wire.begin(35,36,100000);Wire.setTimeOut(100);nfcReady=reader.begin();
 mbedtls_ecdsa_init(&rootKey);mbedtls_ecdsa_init(&issuerKey);mbedtls_ecdsa_init(&cardKey);
 cryptoReady=mbedtls_ecdsa_genkey(&rootKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0 && mbedtls_ecdsa_genkey(&issuerKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0 && mbedtls_ecdsa_genkey(&cardKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0;
 uint8_t secret[8];esp_fill_random(secret,8);apPassword=hex(secret,8);WiFi.mode(WIFI_AP);WiFi.softAP("ESP32-NFC-Lab",apPassword.c_str(),1,0,2);
 Serial.printf("\nNFC Lab WiFi password: %s\nOpen http://192.168.4.1\nPN532: %s\n",apPassword.c_str(),nfcReady?"ready":"not detected");
 state["status"]="Ready — press Scan while holding a card";
 server.on("/",HTTP_GET,[]{server.send_P(200,"text/html",WEB_PAGE);});
 server.on("/api/state",HTTP_GET,[]{state["readerReady"]=nfcReady;sendJson(state);});
 server.on("/api/scan",HTTP_POST,[]{if(!nfcReady)nfcReady=reader.begin();if(!nfcReady){server.send(503,"text/plain","PN532 not detected");return;}scanRequested=true;server.send(202,"text/plain","Scanning");});
 server.on("/api/clear",HTTP_POST,[]{state.clear();state["status"]="Cleared";server.send(200,"text/plain","Cleared");});
 server.on("/api/demo",HTTP_POST,demo);server.begin();
}
void loop(){server.handleClient();if(scanRequested){scanRequested=false;scan();}delay(2);}
