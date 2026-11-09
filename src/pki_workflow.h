#pragma once
#include <Preferences.h>
#include "emv_pki.h"
#include "pki_selftest.h"
Preferences pkiStore;
JsonDocument capkConfig,enrollments;
using emvpki::Bytes;
using emvpki::Key;
Bytes bytesOf(const String &s){return emvpki::unhex(std::string(s.c_str()));}
String bytesHex(const Bytes &b){return hex(b.data(),b.size());}
Bytes cardTag(const char *tag){
 Bytes result;bool found=false;
 for(JsonObject field:state["fields"].as<JsonArray>())if(field["tag"].as<String>()==tag){Bytes b=bytesOf(field["hex"].as<String>());if(found && result!=b)return {};result=b;found=true;}
 return result;
}
String sha256Hex(const String &s){uint8_t hash[32];mbedtls_sha256_ret((const uint8_t*)s.c_str(),s.length(),hash,0);return hex(hash,32);}
Key jsonKey(JsonVariantConst value){return {bytesOf(value["modulus"].as<String>()),bytesOf(value["exponent"].as<String>())};}
void showKey(const Key &key){
 state["publicKey"]["algorithm"]="RSA";state["publicKey"]["modulus"]=bytesHex(key.modulus);state["publicKey"]["exponent"]=bytesHex(key.exponent);
 state["publicKey"]["fingerprint"]=sha256Hex(bytesHex(key.modulus)+":"+bytesHex(key.exponent));
}
void verifyCardProof(){
 state["signatureVerified"]=false;state["retapVerified"]=false;state["chainTrusted"]=false;
 state["trustPolicy"]="Key continuity demo. Certificate expiry, CAPK provenance and revocation are not validated.";
 auto stop=[](const String &why){state["verification"]=why;};
 if(state["status"].as<String>()!="Inspection complete"){stop("Not verified: inspection incomplete");return;}
 String pan=state["pan"] | "",aid=state["aid"] | "";
 if(pan.isEmpty() || aid.length()<10){stop("Not verified: PAN/application unavailable");return;}
 String id=sha256Hex(aid+":"+pan);state["credentialId"]=id;
 bool enrolled=enrollments[id].is<JsonObject>();state["enrolled"]=enrolled;
 Key key;
 if(enrolled){key=jsonKey(enrollments[id]["publicKey"]);state["keySource"]="Previously enrolled public key";}
 else{
  state["keySource"]="EMV certificate recovery against user-configured CAPK";
  String index=state["caIndex"] | "";
  if(capkConfig["rid"].as<String>()!=aid.substring(0,10) || capkConfig["index"].as<String>()!=index){
   state["neededCapkRid"]=aid.substring(0,10);state["neededCapkIndex"]=index;
   stop("Enrollment needs the matching CAPK: import its public modulus/exponent, then retap");return;
  }
  if(!authRecordsComplete){stop("Not verified: offline authentication records incomplete");return;}
  Bytes staticData=authRecords,tagList=cardTag("9F4A");
  if(!tagList.empty()){
   if(tagList!=Bytes{0x82}){stop("Unsupported static authentication tag list (only 82 supported)");return;}
   Bytes aip=bytesOf(state["aip"].as<String>());if(aip.size()!=2){stop("Missing AIP for certificate hash");return;}emvpki::append(staticData,aip);
  }
  Key issuer;std::string error;
  if(!emvpki::certificate(jsonKey(capkConfig.as<JsonVariantConst>()),cardTag("90"),cardTag("92"),cardTag("9F32"),{},pan.c_str(),false,issuer,error)){
   stop(String("Issuer key recovery failed: ")+error.c_str());return;
  }
  if(!emvpki::certificate(issuer,cardTag("9F46"),cardTag("9F48"),cardTag("9F47"),staticData,pan.c_str(),true,key,error)){
   stop(String("Card key recovery failed: ")+error.c_str());return;
  }
  state["certificateHashesVerified"]=true;
 }
 showKey(key);
 Bytes signature,suffix;uint8_t expectedFormat=0x05;
 if(state["requestedSignature"].is<String>()){
  signature=bytesOf(state["requestedSignature"].as<String>());suffix=bytesOf(state["signingChallenge"].as<String>());
  if(suffix.size()!=4){stop("Not verified: DDA challenge missing");return;}state["proofMethod"]="DDA";
 }else if(state["dynamicSignature"].is<String>() && state["fddaRequested"].as<bool>()){
  Bytes nonce=bytesOf(state["terminalData"]["9F37"].as<String>()),amount=bytesOf(state["terminalData"]["9F02"].as<String>()),currency=bytesOf(state["terminalData"]["5F2A"].as<String>()),related=cardTag("9F69");
  if(!emvpki::visaFddaInput(nonce,amount,currency,related,cardTag("9F27"),suffix,expectedFormat)){stop("Unsupported/missing Visa fDDA v1 inputs (9F37,9F02,5F2A,9F69,CID)");return;}
  Bytes ctq=cardTag("9F6C");
  if(related.size()>=7 && !ctq.empty() && (ctq.size()!=2 || ctq[0]!=related[5] || ctq[1]!=related[6])){stop("fDDA CTQ mismatch between GPO and signed Card Authentication Related Data");return;}
  signature=bytesOf(state["dynamicSignature"].as<String>());state["proofMethod"]="Visa fDDA v1";
 }else{stop("Public key available; no supported dynamic signature returned");return;}
 uint8_t formatByte[]={expectedFormat};state["signedDataFormat"]=hex(formatByte,1);
 std::string error;bool valid=emvpki::verifySignature(key,signature,suffix,error,expectedFormat);
 state["signatureVerified"]=valid;state["retapVerified"]=valid && enrolled;
 state["signingStatus"]=valid?"Card signature verified with RSA public key":"Card signature returned; RSA verification failed";
 stop(valid?(enrolled?"RETAP VERIFIED: fresh signature matches enrolled public key":"Fresh card signature verified; ready for explicit enrollment"):(String("SIGNATURE FAILED: ")+error.c_str()));
}
void pkiConfig(int client=-1){JsonDocument doc;doc["capk"].set(capkConfig.as<JsonVariant>());doc["enrollments"].set(enrollments.as<JsonVariant>());push("pki",doc,client);}
bool saveEnrollments(){String text;serializeJson(enrollments,text);return pkiStore.putString("enrollments",text)==text.length();}
void pkiSetup(){
 pkiStore.begin("nfcpki",false);
 deserializeJson(capkConfig,pkiStore.getString("capk","{}"));deserializeJson(enrollments,pkiStore.getString("enrollments","{}"));
 server.on("/api/pki/selftest",HTTP_POST,[]{std::string failure;JsonDocument doc;doc["passed"]=pkiSelfTest(failure);doc["detail"]=failure.empty()?"RSA certificate recovery, DDA/fDDA and negative checks passed":failure.c_str();doc["fixtureType"]="Synthetic public-only RSA test vectors; actual ESP32 verifier";sendJson(doc);});
 server.on("/api/pki",HTTP_GET,[]{JsonDocument doc;doc["capk"].set(capkConfig.as<JsonVariant>());doc["enrollments"].set(enrollments.as<JsonVariant>());sendJson(doc);});
 server.on("/api/pki/capk",HTTP_POST,[]{
  JsonDocument doc;if(server.arg("plain").length()>4096 || deserializeJson(doc,server.arg("plain"))){server.send(400,"text/plain","Invalid CAPK JSON");return;}
  String rid=doc["rid"].as<String>(),index=doc["index"].as<String>();rid.toUpperCase();index.toUpperCase();Key key=jsonKey(doc.as<JsonVariantConst>());
  if(bytesOf(rid).size()!=5 || bytesOf(index).size()!=1 || !emvpki::keyValid(key)){server.send(400,"text/plain","Expected RID (10 hex), index (2 hex), RSA modulus (64–256 bytes) and exponent 03 or 010001");return;}
  JsonDocument clean;clean["rid"]=rid;clean["index"]=index;clean["modulus"]=bytesHex(key.modulus);clean["exponent"]=bytesHex(key.exponent);
  String text;serializeJson(clean,text);if(pkiStore.putString("capk",text)!=text.length()){server.send(500,"text/plain","Failed to save CAPK");return;}
  capkConfig.set(clean.as<JsonVariant>());pkiConfig();server.send(200,"text/plain","CAPK saved; retap card to recover its public key");
 });
 server.on("/api/pki/enroll",HTTP_POST,[]{
  JsonDocument request;if(deserializeJson(request,server.arg("plain"))){server.send(400,"text/plain","Invalid JSON");return;}
  String id=request["id"].as<String>();uint32_t scanId=request["scanId"] | 0;
  if(enrollments[id].is<JsonObject>()){server.send(409,"text/plain","Already enrolled; existing keys are never silently replaced");return;}
  if(enrollments.size()>=8){server.send(409,"text/plain","Eight enrollments maximum; forget one first");return;}
  for(auto &card:cards)if(card["credentialId"].as<String>()==id && card["scanId"].as<uint32_t>()==scanId && card["signatureVerified"].as<bool>() && card["certificateHashesVerified"].as<bool>()){
   JsonObject entry=enrollments[id].to<JsonObject>();entry["publicKey"].set(card["publicKey"]);entry["aid"]=card["aid"].as<String>();entry["policy"]="Explicit enrollment / public key continuity; not bank trust validation";
   if(!saveEnrollments()){enrollments.remove(id);server.send(500,"text/plain","Failed to save enrollment");return;}
   pkiConfig();server.send(200,"text/plain","Public key enrolled; remove card and retap for verification");return;
  }
  server.send(409,"text/plain","Enrollment requires a retained scan with a verified fresh signature and recovered certificate hashes");
 });
 server.on("/api/pki/forget",HTTP_POST,[]{
  JsonDocument request;if(deserializeJson(request,server.arg("plain"))){server.send(400,"text/plain","Invalid JSON");return;}
  String id=request["id"].as<String>();if(!enrollments[id].is<JsonObject>()){server.send(404,"text/plain","Enrollment not found");return;}
  JsonDocument before;before.set(enrollments.as<JsonVariant>());enrollments.remove(id);
  if(!saveEnrollments()){enrollments.set(before.as<JsonVariant>());server.send(500,"text/plain","Failed to save change");return;}
  pkiConfig();server.send(200,"text/plain","Enrollment forgotten");
 });
}
