#pragma once
#include <vector>
#include <string>
#include <algorithm>
#include <stdint.h>
#ifdef NFC_HOST_OPENSSL
#include <openssl/bn.h>
#include <openssl/sha.h>
#else
#include <mbedtls/bignum.h>
#include <mbedtls/sha1.h>
#endif
namespace emvpki {
using Bytes=std::vector<uint8_t>;
struct Key { Bytes modulus,exponent; };
inline Bytes unhex(const std::string &s){
 if(s.size()%2)return {};Bytes b;for(size_t i=0;i<s.size();i+=2){unsigned v=0;for(size_t j=0;j<2;j++){char c=s[i+j];int n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;if(n<0)return {};v=v*16+n;}b.push_back(v);}return b;
}
inline void append(Bytes &to,const Bytes &b){to.insert(to.end(),b.begin(),b.end());}
inline bool keyValid(const Key &k){return k.modulus.size()>=64 && k.modulus.size()<=256 && k.modulus[0] && (k.modulus.back()&1) && (k.exponent==Bytes{3} || k.exponent==Bytes{1,0,1});}
inline Bytes sha1(const Bytes &data){Bytes h(20);
#ifdef NFC_HOST_OPENSSL
 SHA1(data.data(),data.size(),h.data());
#else
 if(mbedtls_sha1_ret(data.data(),data.size(),h.data()))return {};
#endif
 return h;
}
inline bool recover(const Key &key,const Bytes &signature,Bytes &out){
 if(!keyValid(key) || signature.size()!=key.modulus.size())return false;out.resize(signature.size());
#ifdef NFC_HOST_OPENSSL
 BN_CTX *ctx=BN_CTX_new();BIGNUM *n=BN_bin2bn(key.modulus.data(),key.modulus.size(),nullptr),*e=BN_bin2bn(key.exponent.data(),key.exponent.size(),nullptr),*s=BN_bin2bn(signature.data(),signature.size(),nullptr),*r=BN_new();
 bool ok=ctx && n && e && s && r && BN_cmp(s,n)<0 && BN_mod_exp(r,s,e,n,ctx)==1 && BN_bn2binpad(r,out.data(),out.size())==int(out.size());
 BN_free(n);BN_free(e);BN_free(s);BN_free(r);BN_CTX_free(ctx);return ok;
#else
 mbedtls_mpi n,e,s,r;mbedtls_mpi_init(&n);mbedtls_mpi_init(&e);mbedtls_mpi_init(&s);mbedtls_mpi_init(&r);
 bool ok=!mbedtls_mpi_read_binary(&n,key.modulus.data(),key.modulus.size()) && !mbedtls_mpi_read_binary(&e,key.exponent.data(),key.exponent.size()) && !mbedtls_mpi_read_binary(&s,signature.data(),signature.size()) && mbedtls_mpi_cmp_mpi(&s,&n)<0 && !mbedtls_mpi_exp_mod(&r,&s,&e,&n,nullptr) && !mbedtls_mpi_write_binary(&r,out.data(),out.size());
 mbedtls_mpi_free(&n);mbedtls_mpi_free(&e);mbedtls_mpi_free(&s);mbedtls_mpi_free(&r);return ok;
#endif
}
inline bool bcdDigits(const uint8_t *data,size_t size,std::string &digits){
 digits.clear();bool padding=false;for(size_t i=0;i<size*2;i++){unsigned v=(i&1)?data[i/2]&15:data[i/2]>>4;if(v==15){padding=true;continue;}if(v>9 || padding)return false;digits.push_back(char('0'+v));}return true;
}
// Verify certificate hash, algorithms, identifier/PAN and key assembly. Expiry/revocation policy is separate.
inline bool certificate(const Key &parent,const Bytes &sig,const Bytes &remainder,const Bytes &exponent,const Bytes &staticData,const std::string &pan,bool icc,Key &key,std::string &error){
 auto bad=[&](const char *why){error=why;return false;};Bytes r;
 if(!recover(parent,sig,r))return bad("RSA certificate recovery failed");
 size_t fixed=icc?21:15,identifier=icc?10:4;
 if(r.size()<fixed+21 || r[0]!=0x6a || r[1]!=(icc?4:2) || r.back()!=0xbc)return bad("Invalid certificate format");
 if(r[fixed-4]!=1 || r[fixed-3]!=1)return bad("Only EMV RSA/SHA-1 certificates are supported");
 std::string identity;if(!bcdDigits(r.data()+2,identifier,identity))return bad("Invalid certificate PAN encoding");
 if(icc?identity!=pan:identity.size()<3 || identity.size()>pan.size() || pan.compare(0,identity.size(),identity)!=0)return bad("Certificate PAN/issuer prefix mismatch");
 unsigned month=(r[2+identifier]>>4)*10+(r[2+identifier]&15);
 if((r[2+identifier]&15)>9 || (r[2+identifier]>>4)>9 || month<1 || month>12 || (r[3+identifier]&15)>9 || (r[3+identifier]>>4)>9)return bad("Invalid certificate expiry encoding");
 size_t length=r[fixed-2],embedded=r.size()-fixed-21,needed=length>embedded?length-embedded:0;
 if(exponent.size()!=r[fixed-1] || remainder.size()!=needed)return bad("Certificate remainder/exponent length mismatch");
 if(length<embedded)for(size_t i=fixed+length;i<r.size()-21;i++)if(r[i]!=0xbb)return bad("Invalid certificate key padding");
 Bytes hashInput(r.begin()+1,r.end()-21);append(hashInput,remainder);append(hashInput,exponent);append(hashInput,staticData);
 Bytes hash=sha1(hashInput);if(hash.size()!=20 || !std::equal(hash.begin(),hash.end(),r.end()-21))return bad("Certificate hash mismatch (static records/remainder/key)");
 key.modulus.assign(r.begin()+fixed,r.begin()+fixed+std::min(length,embedded));append(key.modulus,remainder);key.exponent=exponent;
 if(!keyValid(key))return bad("Unsupported recovered RSA key");error.clear();return true;
}
// Kernel 3 CARD (9F69) is 5–16 bytes; seven bytes is common (version + UN + CTQ).
inline bool visaFddaInput(const Bytes &nonce,const Bytes &amount,const Bytes &currency,const Bytes &related,const Bytes &cid,Bytes &suffix,uint8_t &format){
 if(nonce.size()!=4 || amount.size()!=6 || currency.size()!=2 || related.size()<5 || related.size()>16 || related[0]!=1 || cid.size()!=1)return false;
 unsigned type=cid[0]&0xc0;
 if(type!=0x40 && type!=0x80)return false;
 format=type==0x80?0x95:0x05;
 suffix=nonce;append(suffix,amount);append(suffix,currency);append(suffix,related);return true;
}
inline bool verifySignature(const Key &key,const Bytes &signature,const Bytes &terminalSuffix,std::string &error,uint8_t expectedFormat=0x05){
 auto bad=[&](const char *why){error=why;return false;};Bytes r;
 if(expectedFormat!=0x05 && expectedFormat!=0x95)return bad("Unsupported SDAD format policy");
 if(terminalSuffix.size()<4)return bad("Missing fresh terminal challenge");
 if(!recover(key,signature,r) || r.size()<27 || r[0]!=0x6a || r[1]!=expectedFormat || r[2]!=1 || r.back()!=0xbc)return bad("Invalid SDAD RSA recovery/format");
 size_t dynamic=r[3],hashAt=r.size()-21;
 if(dynamic<3 || dynamic>hashAt-4 || r[4]<2 || r[4]>8 || size_t(r[4])+1>dynamic)return bad("Malformed signed dynamic data");
 for(size_t i=4+dynamic;i<hashAt;i++)if(r[i]!=0xbb)return bad("Invalid SDAD padding");
 Bytes input(r.begin()+1,r.begin()+hashAt);append(input,terminalSuffix);Bytes hash=sha1(input);
 if(hash.size()!=20 || !std::equal(hash.begin(),hash.end(),r.begin()+hashAt))return bad("Signature hash mismatch: wrong key, challenge or transaction data");
 error.clear();return true;
}
}
