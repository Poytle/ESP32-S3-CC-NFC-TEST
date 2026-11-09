#pragma once
#include <ESPWebServerSecure.hpp>
#include <WebsocketHandler.hpp>
#include <WebsocketNode.hpp>
#include <Preferences.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>
#include <mbedtls/oid.h>
#include <vector>
#include <mbedtls/base64.h>
#include <ArduinoJson.h>
#include <functional>
#include <algorithm>

// Preserve the existing HTTP route API while keeping JSON request bodies reusable.
class SecureWebServer : public ESPWebServerSecure {
 bool bodyRead_=false;String body_;
public:
 explicit SecureWebServer(int port):ESPWebServerSecure(port){}
 void on(const String &uri,HTTPMethod method,THandlerFunction fn){
  ESPWebServer::on(uri,method,[this,fn](){bodyRead_=false;body_="";sendHeader("Cache-Control","no-store");fn();body_="";});
 }
 String arg(String name){if(name!="plain")return ESPWebServer::arg(name);if(!bodyRead_){body_=ESPWebServer::arg(name);bodyRead_=true;}return body_;}
 void sendBytes(int code,const char *type,const uint8_t *data,size_t length){
  _activeResponse->setStatusCode(code);_activeResponse->setHeader("Content-Type",type);_activeResponse->setHeader("Content-Length",std::to_string(length));
  for(size_t offset=0;offset<length;){size_t count=std::min(size_t(1024),length-offset);size_t written=_activeResponse->write(data+offset,count);if(!written || written>count){_activeResponse->error();return;}offset+=written;}
 }
 void send(int code,const char *type,const String &body){sendBytes(code,type,(const uint8_t*)body.c_str(),body.length());}
 void send_P(int code,PGM_P type,PGM_P content){sendBytes(code,type,(const uint8_t*)content,strlen_P(content));}
 void registerSocket(httpsserver::WebsocketNode *node){_server->registerNode(node);}
 bool running(){return _server->isRunning();}
};

class SecureSocketHub {
 class Handler:public httpsserver::WebsocketHandler {
 public:
  int slot=-1;bool pending=true;
  ~Handler(){onClose();}
  void onClose() override {if(slot>=0 && instance()->clients_[slot]==this)instance()->clients_[slot]=nullptr;}
 };
 uint32_t sequence_=0;
 Handler *clients_[4]={};std::function<void(uint8_t)> connected_;
 static SecureSocketHub *&instance(){static SecureSocketHub *hub=nullptr;return hub;}
 static httpsserver::WebsocketHandler *create(){
  Handler *handler=new Handler();for(int i=0;i<4;i++)if(!instance()->clients_[i]){handler->slot=i;instance()->clients_[i]=handler;break;}return handler;
 }
public:
 void begin(SecureWebServer &server){instance()=this;server.registerSocket(new httpsserver::WebsocketNode("/ws",&create));}
 void onConnect(std::function<void(uint8_t)> fn){connected_=fn;}
 // Connection callbacks run after the TLS/WebSocket handshake has completed.
 void loop(){for(int i=0;i<4;i++)if(clients_[i] && clients_[i]->pending){clients_[i]->pending=false;if(connected_)connected_(i);}}
 void sendTXT(uint8_t client,String &text){
  if(client>=4 || !clients_[client])return;
  if(text.length()<=4096){clients_[client]->send(std::string(text.c_str(),text.length()),httpsserver::WebsocketHandler::SEND_TYPE_TEXT);return;}
  // Keep each SSL_write well below a TLS record. Base64 preserves split UTF-8 bytes.
  uint32_t id=++sequence_;size_t total=(text.length()+1023)/1024;
  for(size_t index=0;index<total;index++){
   uint8_t encoded[1369];size_t length=0,offset=index*1024,count=std::min(size_t(1024),text.length()-offset);
   if(mbedtls_base64_encode(encoded,sizeof(encoded),&length,(const uint8_t*)text.c_str()+offset,count))return;
   encoded[length]=0;JsonDocument fragment;fragment["type"]="chunk";fragment["id"]=id;fragment["index"]=index;fragment["total"]=total;fragment["data"]=(const char*)encoded;
   String payload;serializeJson(fragment,payload);clients_[client]->send(std::string(payload.c_str(),payload.length()),httpsserver::WebsocketHandler::SEND_TYPE_TEXT);
  }
 }
 void broadcastTXT(String &text){for(int i=0;i<4;i++)if(clients_[i] && !clients_[i]->pending)sendTXT(i,text);}
};

namespace localtls {
static std::vector<uint8_t> certificate,key;
inline int entropy(void *,unsigned char *out,size_t n){esp_fill_random(out,n);delay(1);return 0;}
inline bool validPair(){
 mbedtls_x509_crt crt;mbedtls_pk_context pk;mbedtls_x509_crt_init(&crt);mbedtls_pk_init(&pk);
 bool ok=!mbedtls_x509_crt_parse_der(&crt,certificate.data(),certificate.size()) && !mbedtls_pk_parse_key(&pk,key.data(),key.size(),nullptr,0) && !mbedtls_pk_check_pair(&crt.pk,&pk);
 mbedtls_pk_free(&pk);mbedtls_x509_crt_free(&crt);return ok;
}
inline bool initialize(SecureWebServer &server){
 Preferences store;if(!store.begin("nfctls",false))return false;
 size_t c=store.getBytesLength("cert"),k=store.getBytesLength("key");
 bool loaded=false;
 if(c>0 && c<=4096 && k>0 && k<=4096){certificate.resize(c);key.resize(k);loaded=store.getBytes("cert",certificate.data(),c)==c && store.getBytes("key",key.data(),k)==k && validPair();}
 if(!loaded){
  Serial.println("Generating device HTTPS certificate (first boot may take several seconds)...");
  mbedtls_pk_context pk;mbedtls_pk_init(&pk);mbedtls_x509write_cert crt;mbedtls_x509write_crt_init(&crt);mbedtls_mpi serial;mbedtls_mpi_init(&serial);
  uint8_t serialBytes[16];esp_fill_random(serialBytes,sizeof(serialBytes));serialBytes[0]&=0x7f;serialBytes[0]|=1;
  const char *name="CN=192.168.4.1,O=ESP32 NFC Lab";
  // SubjectAltName: IP 192.168.4.1 and DNS esp32-nfc-lab.local.
  std::vector<uint8_t> names={0x30,0,0x87,4,192,168,4,1,0x82,0};
  const char *dns="esp32-nfc-lab.local";
  names[1]=uint8_t(8+strlen(dns));names[9]=uint8_t(strlen(dns));names.insert(names.end(),dns,dns+strlen(dns));
  bool ok=!mbedtls_pk_setup(&pk,mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) && !mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk),entropy,nullptr,2048,65537) && !mbedtls_mpi_read_binary(&serial,serialBytes,sizeof(serialBytes));
  mbedtls_x509write_crt_set_version(&crt,MBEDTLS_X509_CRT_VERSION_3);mbedtls_x509write_crt_set_md_alg(&crt,MBEDTLS_MD_SHA256);mbedtls_x509write_crt_set_subject_key(&crt,&pk);mbedtls_x509write_crt_set_issuer_key(&crt,&pk);
  ok=ok && !mbedtls_x509write_crt_set_serial(&crt,&serial) && !mbedtls_x509write_crt_set_subject_name(&crt,name) && !mbedtls_x509write_crt_set_issuer_name(&crt,name) && !mbedtls_x509write_crt_set_validity(&crt,"20200101000000","20400101000000") && !mbedtls_x509write_crt_set_basic_constraints(&crt,0,-1) && !mbedtls_x509write_crt_set_key_usage(&crt,MBEDTLS_X509_KU_DIGITAL_SIGNATURE|MBEDTLS_X509_KU_KEY_ENCIPHERMENT) && !mbedtls_x509write_crt_set_extension(&crt,MBEDTLS_OID_SUBJECT_ALT_NAME,MBEDTLS_OID_SIZE(MBEDTLS_OID_SUBJECT_ALT_NAME),0,names.data(),names.size());
  std::vector<uint8_t> buffer(4096);int count=ok?mbedtls_pk_write_key_der(&pk,buffer.data(),buffer.size()):-1;
  if(count>0)key.assign(buffer.end()-count,buffer.end());else ok=false;
  count=ok?mbedtls_x509write_crt_der(&crt,buffer.data(),buffer.size(),entropy,nullptr):-1;
  if(count>0)certificate.assign(buffer.end()-count,buffer.end());else ok=false;
  mbedtls_x509write_crt_free(&crt);mbedtls_mpi_free(&serial);mbedtls_pk_free(&pk);
  if(!ok || !validPair() || store.putBytes("cert",certificate.data(),certificate.size())!=certificate.size() || store.putBytes("key",key.data(),key.size())!=key.size()){store.end();return false;}
 }
 store.end();server.setServerKeyAndCert(key.data(),key.size(),certificate.data(),certificate.size());return true;
}
}
