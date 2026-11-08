#pragma once
#include <stdint.h>
#include <stddef.h>
#include <cstring>
inline uint32_t millis(){static uint32_t t=0;return ++t;}
inline void delay(unsigned){}
struct FakeSerial { template<class... T> void printf(const char *,T...){} };
static FakeSerial Serial;
