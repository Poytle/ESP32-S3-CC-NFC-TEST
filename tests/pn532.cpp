#include "pn532.h"
#include <algorithm>
std::vector<uint8_t> frame(const std::vector<uint8_t> &payload,uint8_t command=2){
 size_t count=payload.size()+2;std::vector<uint8_t> b={1,0,0,255};
 if(count<255){b.push_back(count);b.push_back(uint8_t(-count));}
 else {b.push_back(255);b.push_back(255);b.push_back(count>>8);b.push_back(count);b.push_back(uint8_t(-((count>>8)+(count&255))));}
 b.push_back(0xd5);b.push_back(command+1);b.insert(b.end(),payload.begin(),payload.end());
 uint8_t sum=0;size_t start=count<255?6:9;for(size_t i=start;i<b.size();i++)sum+=b[i];b.push_back(uint8_t(-sum));b.push_back(0);return b;
}
std::vector<uint8_t> response(size_t size){std::vector<uint8_t> data;for(size_t i=0;i<size;i++)data.push_back(uint8_t(i));return frame(data);}
void appendQueue(const std::vector<uint8_t> &b){
 for(auto data:std::vector<std::vector<uint8_t>>{{1},{1,0,0,255,0,255,0},{1},std::vector<uint8_t>(b.begin(),b.begin()+9),{1},b})Wire.reads.push_back(data);
}
void queue(const std::vector<uint8_t> &b){Wire.reads.clear();appendQueue(b);}
int main(){
 // Reproduce the reported 270 -> 14 legacy return-value truncation.
 auto exact270=response(257);assert(exact270.size()==270);
 Wire=FakeWire();Wire.reads.push_back(exact270);
 assert(Wire.requestFrom(0x24,int(exact270.size()))==14);
 assert(Wire.available()==270); // The bus read succeeded; only its returned count wrapped.
 Wire=FakeWire();Wire.reads.push_back(exact270);
 assert(Wire.requestFrom(uint16_t(0x24),size_t(exact270.size()),true)==270);
 PN532 reader;uint8_t cmd=2,out[1024];
 for(size_t size:{size_t(0),size_t(4),size_t(245),size_t(246),size_t(256),size_t(257)}){
  Wire=FakeWire();queue(response(size));size_t n=sizeof(out);
  assert(reader.command(&cmd,1,out,n));assert(n==size);assert(Wire.reads.empty());assert(Wire.writes.size()==2);
  assert((Wire.writes[1]==std::vector<uint8_t>{0,0,255,255,0,0}));
  for(size_t i=0;i<n;i++)assert(out[i]==uint8_t(i));
 }
 Wire=FakeWire();Wire.reads={{},{},{}};size_t n=1024;assert(!reader.command(&cmd,1,out,n));assert(Wire.reads.empty());
 assert(std::strstr(reader.lastError(),"I2C read failed"));
 Wire=FakeWire();Wire.writeError=2;assert(!reader.begin());assert(std::strstr(reader.lastError(),"No device ACK"));
 Wire=FakeWire();auto broken=response(4);broken.back()=1;queue(broken);n=1024;assert(!reader.command(&cmd,1,out,n));
 // Temporary address NACK during readiness polling must not abort the operation.
 Wire=FakeWire();queue(response(4));Wire.reads.push_front({});n=1024;assert(reader.command(&cmd,1,out,n));assert(!std::strcmp(reader.lastError(),"none"));
 // Retry a failed full extended I2C read by fetching the saved response, never reissuing the command.
 Wire=FakeWire();auto big=response(256);queue(big);Wire.reads.pop_back();Wire.reads.push_back({});Wire.reads.push_back({1});Wire.reads.push_back(big);n=1024;
 assert(reader.command(&cmd,1,out,n));assert(n==256);assert(Wire.writes.size()==3);assert(Wire.writes[1]==Wire.writes[2]);assert(!std::strcmp(reader.lastError(),"none"));
 // Exhausted read recovery retains precise byte counts and phase.
 Wire=FakeWire();queue(big);Wire.reads.pop_back();Wire.reads.push_back({});Wire.reads.push_back({1});Wire.reads.push_back({});n=1024;
 assert(!reader.command(&cmd,1,out,n));assert(reader.readRequested()==big.size());assert(reader.readReceived()==0);assert(!std::strcmp(reader.phase(),"response frame"));
 // Chained status 0x40 is successful data with more to fetch, not an RF error.
 Wire=FakeWire();queue(frame({0x40,0x11,0x22},0x40));appendQueue(frame({0,0x33,0x90,0},0x40));n=1024;
 uint8_t apdu[]={0,0xb2,2,0x14,0};assert(reader.exchange(apdu,5,out,n));assert(n==5);const uint8_t expected[]={0x11,0x22,0x33,0x90,0};assert(!std::memcmp(out,expected,n));
 assert(Wire.writes.size()==4);assert(Wire.writes[2][3]==3);assert(Wire.writes[2][6]==0x40 && Wire.writes[2][7]==1); // continuation has no APDU
 Wire=FakeWire();queue(frame({0x80,0x12,0x90,0},0x40));n=1024;assert(reader.exchange(apdu,5,out,n));assert(n==2 && out[0]==0x90); // strip NAD
 Wire=FakeWire();queue(frame({1},0x40));n=1024;assert(!reader.exchange(apdu,5,out,n));assert(reader.exchangeStatus()==1);assert(std::strstr(reader.lastError(),"0x01"));
 Wire=FakeWire();queue(frame({0,1,2,3},0x40));n=2;assert(!reader.exchange(apdu,5,out,n));assert(std::strstr(reader.lastError(),"APDU buffer"));
 Wire=FakeWire();for(unsigned i=0;i<8;i++)appendQueue(frame({0x40,1},0x40));n=1024;assert(!reader.exchange(apdu,5,out,n));assert(std::strstr(reader.lastError(),"8 fragments"));
}
