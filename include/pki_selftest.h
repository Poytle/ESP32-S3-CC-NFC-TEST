#pragma once
#include "pki_test_vectors.h"
inline bool pkiSelfTest(std::string &failure){
 using namespace emvpki;using namespace pki_vectors;
 auto check=[&](bool ok,const char *name){if(!ok)failure=name;return ok;};
 Key root{root_n(),exponent()},issuer,card;std::string error;const std::string pan="4111111111111111";
 if(!check(certificate(root,issuer_cert(),issuer_rem(),exponent(),{},pan,false,issuer,error),"issuer certificate"))return false;
 if(!check(issuer.modulus==issuer_n(),"issuer modulus"))return false;
 if(!check(certificate(issuer,card_cert(),card_rem(),exponent(),static_data(),pan,true,card,error),"ICC certificate"))return false;
 if(!check(card.modulus==card_n(),"ICC modulus"))return false;
 if(!check(verifySignature(card,dda_sig(),nonce(),error),"DDA valid challenge"))return false;
 Bytes changed=nonce();changed[0]^=1;
 if(!check(!verifySignature(card,dda_sig(),changed,error),"DDA replay rejection"))return false;
 if(!check(!verifySignature(issuer,dda_sig(),nonce(),error),"wrong enrolled key rejection"))return false;
 if(!check(verifySignature(card,fdda_sig(),fdda_suffix(),error),"fDDA v1"))return false;
 Bytes built;uint8_t format=0;
 Bytes related;
 Bytes all=fdda_suffix();related.assign(all.begin()+12,all.end());
 if(!check(visaFddaInput(nonce(),Bytes(6,0),Bytes{3,0x56},related,Bytes{0x80},built,format) && related.size()==7 && built==all && format==0x95,"7-byte CARD / online format policy"))return false;
 if(!check(verifySignature(card,fdda_online_sig(),built,error,format),"online fDDA format 95"))return false;
 if(!check(!verifySignature(card,fdda_online_sig(),built,error),"DDA rejects format 95"))return false;
 if(!check(!verifySignature(card,fdda_sig(),built,error,0x95),"online fDDA rejects format 05"))return false;
 if(!check(visaFddaInput(nonce(),Bytes(6,0),Bytes{3,0x56},related,Bytes{0x40},built,format) && format==5,"offline format policy"))return false;
 if(!check(!visaFddaInput(nonce(),Bytes(6,0),Bytes{3,0x56},related,Bytes{0},built,format),"AAC rejected"))return false;
 if(!check(!visaFddaInput(nonce(),Bytes(6,0),Bytes{3,0x56},Bytes{1,2,3,4},Bytes{0x80},built,format),"short CARD rejected"))return false;
 changed=fdda_suffix();changed[4]=1;
 if(!check(!verifySignature(card,fdda_sig(),changed,error),"fDDA amount binding"))return false;
 changed=fdda_suffix();changed.back()^=1;
 if(!check(!verifySignature(card,fdda_sig(),changed,error),"fDDA card data binding"))return false;
 if(!check(!verifySignature(card,bad_padding_sig(),nonce(),error),"SDAD padding rejection"))return false;
 changed=static_data();changed[0]^=1;Key invalid;
 if(!check(!certificate(issuer,card_cert(),card_rem(),exponent(),changed,pan,true,invalid,error),"static data hash rejection"))return false;
 if(!check(!certificate(issuer,card_cert(),card_rem(),exponent(),static_data(),"4111111111111112",true,invalid,error),"PAN mismatch rejection"))return false;
 changed=card_rem();changed.pop_back();
 if(!check(!certificate(issuer,card_cert(),changed,exponent(),static_data(),pan,true,invalid,error),"missing remainder rejection"))return false;
 changed=dda_sig();changed[0]^=1;
 if(!check(!verifySignature(card,changed,nonce(),error),"modified signature rejection"))return false;
 if(!check(!verifySignature(card,card.modulus,nonce(),error),"signature out of range"))return false;
 failure.clear();return true;
}
