#include <Arduino.h>
#include <WiFi.h>
#include "secure_web.h"
#include "emv_data.h"
#include "emv_pki.h"
#include <ArduinoJson.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include "pn532.h"
#include "tlv.h"
#include "web_generated.h"
SecureWebServer server(433);ESPWebServer redirectServer(80);bool tlsReady=false; PN532 reader; bool nfcReady=false, scanRequested=false;
JsonDocument state;
SecureSocketHub sockets;
JsonDocument cards[4];
uint32_t scanSequence=0, nextPoll=0, nextReaderRetry=0;
String heldUid, bootId;
unsigned absentPolls=0, nextSlot=0;
uint8_t ddolData[64]; size_t ddolSize=0; bool ddolPresent=false;
size_t fieldBytes=0;
emvpki::Bytes authRecords;bool authRecordsComplete=true;unsigned authRequiredRecords=0,authCollectedRecords=0;
void push(const char *type, JsonDocument &data, int client=-1){
 JsonDocument event;event["type"]=type;event["card"].set(data.as<JsonVariant>());
 String text;serializeJson(event,text);
 if(client<0)sockets.broadcastTXT(text);else sockets.sendTXT(client,text);
}
void publishCard(){
 String pan=state["pan"] | "";String key=pan.length()?String("pan:")+pan:String("uid:")+(state["uid"] | "unknown");
 state["key"]=key;int slot=-1;
 for(int i=0;i<4;i++)if(cards[i]["key"].as<String>()==key){slot=i;break;}
 if(slot<0){slot=nextSlot;nextSlot=(nextSlot+1)%4;cards[slot].clear();}
 uint32_t taps=cards[slot]["taps"] | 0;
 if(cards[slot]["scanId"].as<uint32_t>()!=state["scanId"].as<uint32_t>())taps++;
 state["taps"]=taps;state["readerError"]=reader.lastError();
 cards[slot].set(state.as<JsonVariant>());push("card",state);
}
void readerStatus(int client=-1){JsonDocument doc;doc["firmwareBuild"]=__DATE__ " " __TIME__;doc["httpsPort"]=433;doc["socketPath"]="/ws";doc["bootId"]=bootId;doc["readerReady"]=nfcReady;doc["readerError"]=reader.lastError();push("reader",doc,client);}

mbedtls_ecdsa_context rootKey, issuerKey, cardKey;
bool cryptoReady=false;
int rng(void *, unsigned char *out,size_t n){esp_fill_random(out,n);return 0;}
String hex(const uint8_t *b,size_t n){static const char h[]="0123456789ABCDEF";String s;s.reserve(n*2);while(n--){s+=h[*b>>4];s+=h[*b++&15];}return s;}
void sendJson(JsonDocument &doc){String s;serializeJson(doc,s);server.sendHeader("Cache-Control","no-store");server.send(200,"application/json",s);}
void inspect(const uint8_t *data,size_t size,unsigned depth=0){
 if(depth>8)return; size_t pos=0;Tlv t;
 while(nextTlv(data,size,pos,t)){
  String tag=String(t.tag,HEX);tag.toUpperCase();if(tag.length()%2)tag="0"+tag;
  // Keep every returned primitive TLV, including unknown tags, under a bounded RAM budget.
  if(!t.constructed){
   String value=hex(t.data,t.size);bool duplicate=false;
   for(JsonObject field:state["fields"].as<JsonArray>())if(field["tag"].as<String>()==tag && field["hex"].as<String>()==value){duplicate=true;break;}
   if(!duplicate){
    if(fieldBytes+value.length()<=8192 && state["fields"].size()<128){
     JsonObject field=state["fields"].as<JsonArray>().add<JsonObject>();field["tag"]=tag;field["hex"]=value;
     String text;bool printable=true;for(size_t i=0;i<t.size;i++){if(t.data[i]<32 || t.data[i]>126){printable=false;break;}text+=char(t.data[i]);}
     if(printable && text.length())field["text"]=text;fieldBytes+=value.length();
    }else state["fieldsTruncated"]=true;
   }
  }
  if(t.tag==0x9f49){ddolPresent=true;ddolSize=t.size<=sizeof(ddolData)?t.size:0;if(ddolSize)memcpy(ddolData,t.data,ddolSize);}
  if(t.constructed){inspect(t.data,t.size,depth+1);continue;}
  if(t.tag==0x4f && !state["aid"].is<String>())state["aid"]=hex(t.data,t.size);
  if(t.tag==0x50 || t.tag==0x9f12){String label;for(size_t i=0;i<t.size;i++)label+=t.data[i]>=32 && t.data[i]<127?char(t.data[i]):'?';state["application"]=label;}
  if(t.tag==0x5a || t.tag==0x57){char pan[20];if(decodePan(t.data,t.size,t.tag==0x57,pan,sizeof(pan)))state["pan"]=pan;}
  if(t.tag==0x82)state["aip"]=hex(t.data,t.size);
  if(t.tag==0x8f)state["caIndex"]=hex(t.data,t.size);
  if(t.tag==0x90 || t.tag==0x9f46 || t.tag==0x9f4b){String key=t.tag==0x90?"issuerCertificate":t.tag==0x9f46?"cardCertificate":"dynamicSignature";state[key]=hex(t.data,t.size);}
 }
}
bool findTag(const uint8_t *b,size_t n,uint32_t tag,Tlv &result,unsigned depth=0){if(depth>8)return false;size_t p=0;Tlv t;while(nextTlv(b,n,p,t)){if(t.tag==tag){result=t;return true;}if(t.constructed && findTag(t.data,t.size,tag,result,depth+1))return true;}return false;}
uint8_t response[1024];size_t responseSize;bool apduTransportFailed=false;
bool apdu(const char *name,const uint8_t *cmd,size_t n){
 apduTransportFailed=false;responseSize=sizeof(response);JsonObject log=state["steps"].as<JsonArray>().add<JsonObject>();log["command"]=String(name);
 if(!reader.exchange(cmd,n,response,responseSize) || responseSize<2){
  apduTransportFailed=true;log["status"]="Transport failed";
  log["detail"]=strcmp(reader.lastError(),"none")?reader.lastError():"Card response omitted APDU status words";
  if(reader.exchangeStatus()>=0)log["pn532Status"]=reader.exchangeStatus();
  log["transportPhase"]=reader.phase();
  log["i2cReadRequested"]=reader.readRequested();log["i2cReadReceived"]=reader.readReceived();
  state["failure"].set(log);sockets.loop();return false;
 }
 uint16_t sw=(response[responseSize-2]<<8)|response[responseSize-1];responseSize-=2;uint8_t swBytes[]={uint8_t(sw>>8),uint8_t(sw)};log["status"]=hex(swBytes,2);
 sockets.loop();
 if(sw!=0x9000)return false;inspect(response,responseSize);
 Tlv signature;if(findTag(response,responseSize,0x9f4b,signature))state["dynamicSignatureSource"]=String(name);
 return true;
}
void scan(const uint8_t *uid,size_t uidSize){
 state.clear();authRecords.clear();authRecordsComplete=true;authRequiredRecords=authCollectedRecords=0;fieldBytes=0;ddolSize=0;ddolPresent=false;
 state["fields"].to<JsonArray>();state["scanId"]=++scanSequence;state["seenMs"]=millis();state["signingStatus"]="Pending initial scan";
 state["steps"].to<JsonArray>();state["verification"]="Not authenticated — no EMV trust chain verification performed";
 state["uid"]=hex(uid,uidSize);state["status"]="Card detected";
 uint8_t selectPpse[]={0,0xa4,4,0,14,'2','P','A','Y','.','S','Y','S','.','D','D','F','0','1',0};
 if(!apdu("SELECT PPSE",selectPpse,sizeof(selectPpse))){state["status"]=apduTransportFailed?"Transport failed during SELECT PPSE":"Card found; payment directory unavailable";return;}
 Tlv aid;if(!findTag(response,responseSize,0x4f,aid) || aid.size<5 || aid.size>16){state["status"]="No supported payment application in PPSE";return;}
 state["aid"]=hex(aid.data,aid.size);
 bool visa=state["aid"].as<String>().startsWith("A000000003");
 state["signingMethod"]=visa?"Visa fDDA capture via GPO":"Standalone DDA if advertised";
 state["fddaRequested"]=false;
 uint8_t select[22]={0,0xa4,4,0,uint8_t(aid.size)};memcpy(select+5,aid.data,aid.size);select[5+aid.size]=0;
 if(!apdu("SELECT payment application",select,aid.size+6)){state["status"]=apduTransportFailed?"Transport failed selecting payment application":"Payment application selection rejected";return;}
 // Fill PDOL using neutral terminal values and a fresh unpredictable number.
 uint8_t gpo[255]={0x80,0xa8,0,0,0,0x83,0};size_t total=0;Tlv pdol;
 uint8_t nonce[4];esp_fill_random(nonce,4);state["challenge"]=hex(nonce,4);
 if(findTag(response,responseSize,0x9f38,pdol)){
  size_t p=0;while(p<pdol.size){uint32_t tag=pdol.data[p++];if((tag&31)==31){if(p>=pdol.size)return;uint8_t b=pdol.data[p++];tag=(tag<<8)|b;if(b&128){state["status"]="Unsupported PDOL tag";return;}}
   if(p>=pdol.size)return;size_t len=pdol.data[p++];if(total+len>120){state["status"]="PDOL too large";return;}
   memset(gpo+7+total,0,len);
   if(tag==0x9f37 && len==4)memcpy(gpo+7+total,nonce,4);
   if(tag==0x9f66 && len==4){
    terminalTtq(visa,gpo+7+total);state["terminalTtq"]=hex(gpo+7+total,4);state["fddaRequested"]=visa;
   }
   if((tag==0x9f1a || tag==0x5f2a) && len==2){gpo[7+total]=0x03;gpo[8+total]=0x56;}
   String terminalTag=String(tag,HEX);terminalTag.toUpperCase();if(terminalTag.length()%2)terminalTag="0"+terminalTag;
   state["terminalData"][terminalTag]=hex(gpo+7+total,len);
   total+=len;
  }
 }
 gpo[4]=total+2;gpo[6]=total;gpo[7+total]=0;
 if(!apdu("GET PROCESSING OPTIONS (zero amount)",gpo,total+8)){state["status"]=apduTransportFailed?"Transport failed during GPO":"Card declined inspection GPO";return;}
 uint8_t afl[252];size_t aflSize=0;Tlv t;
 if(findTag(response,responseSize,0x94,t)){aflSize=t.size;if(aflSize<=sizeof(afl))memcpy(afl,t.data,aflSize);else return;}
 else if(findTag(response,responseSize,0x80,t) && t.size>=2){state["aip"]=hex(t.data,2);aflSize=t.size-2;if(aflSize>sizeof(afl))return;memcpy(afl,t.data+2,aflSize);}
 if(aflSize%4){state["status"]="Malformed AFL";return;}
 unsigned records=0;
 for(size_t i=0;i<aflSize;i+=4){uint8_t sfi=afl[i]>>3,first=afl[i+1],last=afl[i+2],offline=afl[i+3];if(sfi<1 || sfi>30 || !first || first>last || last>32 || offline>last-first+1){authRecordsComplete=false;continue;}
  authRequiredRecords+=offline;
  for(unsigned rec=first;rec<=last && records<32;rec++,records++){
   uint8_t cmd[]={0,0xb2,uint8_t(rec),uint8_t((sfi<<3)|4),0};
   String name=String("READ RECORD SFI=")+sfi+" record="+rec;
   bool read=apdu(name.c_str(),cmd,5);
   if(rec-first<offline){
    Tlv record;size_t p=0;
    if(!read || !nextTlv(response,responseSize,p,record) || record.tag!=0x70 || p!=responseSize)authRecordsComplete=false;
    else{const uint8_t *data=sfi<=10?record.data:response;size_t size=sfi<=10?record.size:responseSize;
     if(authRecords.size()+size>8192)authRecordsComplete=false;else{authRecords.insert(authRecords.end(),data,data+size);authCollectedRecords++;}
    }
   }
   if(!read && apduTransportFailed){state["status"]=String("Inspection interrupted at ")+name+": "+state["failure"]["detail"].as<String>();return;}
  }
 }
 if(authCollectedRecords!=authRequiredRecords)authRecordsComplete=false;
 state["status"]="Inspection complete";
}
void requestCardSignature(){
 state["verification"]="Not verified: EMV trust chain verification is not implemented";
 if(state["status"].as<String>()!="Inspection complete"){
  state["signingStatus"]="Not requested: initial inspection did not complete";return;
 }
 if(state["fddaRequested"].as<bool>())state["signingChallenge"]=state["challenge"].as<String>();
 // Contactless fDDA may already return signed data during inspection.
 if(state["dynamicSignature"].is<String>()){
  state["signingStatus"]=String("Dynamic signature received in ")+(state["dynamicSignatureSource"] | "inspection")+" — unverified; separate DDA not requested";
  return;
 }
 if(state["aid"].as<String>().startsWith("A000000003")){
  state["signingChallenge"]=state["challenge"].as<String>();
  state["signingStatus"]=state["fddaRequested"].as<bool>()?
    "Visa fDDA requested during GPO; no signature (9F4B) returned":
    "Visa fDDA not requested: PDOL did not include a supported TTQ";
  return; // Visa contactless fDDA does not use INTERNAL AUTHENTICATE.
 }
 String aip=state["aip"] | "";
 if(aip.length()<2 || !(strtoul(aip.substring(0,2).c_str(),nullptr,16)&0x20)){
  state["signingStatus"]="No standalone DDA advertised; other authentication modes are not implemented";
  return;
 }
 uint8_t nonce[4];esp_fill_random(nonce,4);state["signingChallenge"]=hex(nonce,4);
 uint8_t input[64];size_t inputSize=sizeof(input);const uint8_t defaultDdol[]={0x9f,0x37,4};
 state["ddolSource"]=ddolPresent?"Card 9F49":"Terminal default 9F3704";
 if(!ddaInput(ddolPresent?ddolData:defaultDdol,ddolPresent?ddolSize:sizeof(defaultDdol),nonce,input,inputSize)){
  state["signingStatus"]="Unsupported DDOL: only 9F3704 is implemented; no request sent";return;
 }
 state["signingStatus"]="Requesting card signature";publishCard();sockets.loop();
 uint8_t cmd[70]={0,0x88,0,0,uint8_t(inputSize)};memcpy(cmd+5,input,inputSize);cmd[5+inputSize]=0;
 bool accepted=apdu("INTERNAL AUTHENTICATE",cmd,inputSize+6);
 JsonObject result=state["steps"][state["steps"].size()-1].as<JsonObject>();
 state["signingResponse"].set(result);
 if(!accepted){
  if(apduTransportFailed)state["signingStatus"]=String("Signing transport failure: ")+result["detail"].as<String>();
  else{
   String sw=result["status"].as<String>();const char *reason="card rejected command";
   if(sw=="6D00")reason="INTERNAL AUTHENTICATE instruction not supported";
   else if(sw=="6A81")reason="requested function not supported";
   else if(sw=="6985")reason="conditions of use not satisfied";
   else if(sw=="6982")reason="security conditions not satisfied";
   else if(sw=="6700")reason="incorrect command length";
   else if(sw=="6A80")reason="incorrect command data";
   else if(sw=="6A86")reason="incorrect command parameters";
   state["signingStatus"]=String("INTERNAL AUTHENTICATE ")+sw+": "+reason;
  }
  return;
 }
 Tlv signedData;
 if(findTag(response,responseSize,0x9f4b,signedData) || findTag(response,responseSize,0x80,signedData)){
  state["requestedSignature"]=hex(signedData.data,signedData.size);
  state["signingStatus"]="Card returned signed dynamic data — NOT cryptographically verified";
 }else state["signingStatus"]="Command succeeded but no signed dynamic data returned";
}
#include "pki_workflow.h"
void tapScan(const uint8_t *uid,size_t size){
 scan(uid,size);publishCard();sockets.loop();
 requestCardSignature();verifyCardProof();publishCard();
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
 uint8_t bootNonce[8];esp_fill_random(bootNonce,sizeof(bootNonce));bootId=hex(bootNonce,sizeof(bootNonce));
 Serial.begin(115200);Wire.setBufferSize(1024);Wire.begin(35,36,100000);Wire.setTimeOut(250);nfcReady=reader.begin();
 mbedtls_ecdsa_init(&rootKey);mbedtls_ecdsa_init(&issuerKey);mbedtls_ecdsa_init(&cardKey);
 cryptoReady=mbedtls_ecdsa_genkey(&rootKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0 && mbedtls_ecdsa_genkey(&issuerKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0 && mbedtls_ecdsa_genkey(&cardKey,MBEDTLS_ECP_DP_SECP256R1,rng,nullptr)==0;
 WiFi.mode(WIFI_AP);WiFi.softAP("ESP32-NFC-Lab",nullptr,1,0,2);
 Serial.printf("\nNFC Lab WiFi: ESP32-NFC-Lab (open, no password)\nOpen https://192.168.4.1:433\nPN532: %s\n",nfcReady?"ready":"not detected");
 state["status"]="Ready — tap and hold a card";
 server.on("/",HTTP_GET,[]{server.send_P(200,"text/html",WEB_PAGE);});
 server.on("/api/state",HTTP_GET,[]{state["readerReady"]=nfcReady;state["readerError"]=reader.lastError();sendJson(state);});
 server.on("/api/scan",HTTP_POST,[]{if(!nfcReady){nfcReady=reader.begin();readerStatus();}if(!nfcReady){server.send(503,"text/plain","PN532 not detected");return;}scanRequested=true;server.send(202,"text/plain","Scanning");});
 server.on("/api/clear",HTTP_POST,[]{state.clear();for(auto &card:cards)card.clear();nextSlot=0;push("clear",state);server.send(200,"text/plain","Cleared");});
 server.on("/api/demo",HTTP_POST,demo);
 pkiSetup();
 sockets.begin(server);sockets.onConnect([](uint8_t client){
  readerStatus(client);pkiConfig(client);for(auto &card:cards)if(!card.isNull())push("card",card,client);
 });
 tlsReady=localtls::initialize(server);
 if(tlsReady){server.begin();tlsReady=server.running();}
 if(!tlsReady)Serial.println("HTTPS initialization failed; application is not exposed over HTTP");
 redirectServer.onNotFound([](){
  if(!tlsReady){redirectServer.send(503,"text/plain","HTTPS unavailable; inspect serial log");return;}
  redirectServer.sendHeader("Location",String("https://192.168.4.1:433")+redirectServer.uri());
  redirectServer.sendHeader("Cache-Control","no-store");redirectServer.send(308,"text/plain","Use HTTPS on port 433");
 });
 redirectServer.begin();
}
void loop(){
 redirectServer.handleClient();if(tlsReady)server.handleClient();sockets.loop();
 if(!nfcReady){
  if(int32_t(millis()-nextReaderRetry)>=0){nextReaderRetry=millis()+5000;nfcReady=reader.begin();readerStatus();}
 }else if(scanRequested || int32_t(millis()-nextPoll)>=0){
  bool force=scanRequested;scanRequested=false;nextPoll=millis()+500;
  uint8_t uid[10];size_t size=sizeof(uid);
  if(reader.poll(uid,size)){
   absentPolls=0;String current=hex(uid,size);
   if(force || current!=heldUid){heldUid=current;tapScan(uid,size);}
  }else if(strcmp(reader.lastError(),"none")){
   nfcReady=false;nextReaderRetry=millis()+5000;readerStatus();
  }else if(++absentPolls>=2)heldUid="";
 }
 delay(2);
}
