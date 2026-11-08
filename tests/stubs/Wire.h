#pragma once
#include <vector>
#include <deque>
#include <cassert>
struct FakeWire {
 std::deque<std::vector<uint8_t>> reads;
 std::vector<std::vector<uint8_t>> writes;
 std::vector<uint8_t> tx,rx;size_t pos=0;int writeError=0;
 void beginTransmission(int address){assert(address==0x24);tx.clear();}
 size_t write(const uint8_t *data,size_t n){tx.assign(data,data+n);return n;}
 int endTransmission(){writes.push_back(tx);return writeError;}
 // Match Arduino-ESP32 2.0.17's overloads, including legacy 8-bit return values.
 size_t requestFrom(uint16_t address,size_t n,bool sendStop){assert(sendStop);assert(address==0x24);assert(!reads.empty());rx=reads.front();reads.pop_front();pos=0;if(rx.empty())return 0;assert(rx.size()==n);return n;}
 size_t requestFrom(uint8_t address,size_t n,bool stop){return requestFrom(uint16_t(address),n,stop);}
 uint8_t requestFrom(uint16_t address,uint8_t n,bool stop){return requestFrom(address,size_t(n),stop);}
 uint8_t requestFrom(uint16_t address,uint8_t n,uint8_t stop){return requestFrom(address,size_t(n),bool(stop));}
 uint8_t requestFrom(uint8_t address,uint8_t n,uint8_t stop){return requestFrom(uint16_t(address),size_t(n),bool(stop));}
 uint8_t requestFrom(uint16_t address,uint8_t n){return requestFrom(address,size_t(n),true);}
 uint8_t requestFrom(uint8_t address,uint8_t n){return requestFrom(uint16_t(address),size_t(n),true);}
 uint8_t requestFrom(int address,int n){return requestFrom(uint16_t(address),size_t(n),true);}
 uint8_t requestFrom(int address,int n,int stop){return requestFrom(uint16_t(address),size_t(n),bool(stop));}
 int read(){assert(pos<rx.size());return rx[pos++];}
 int available(){return rx.size()-pos;}
};
static FakeWire Wire;
