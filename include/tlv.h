#pragma once
#include <stddef.h>
#include <stdint.h>
struct Tlv { uint32_t tag; const uint8_t *data; size_t size; bool constructed; };
inline bool nextTlv(const uint8_t *data, size_t size, size_t &offset, Tlv &out) {
  if (offset >= size) return false;
  uint8_t first = data[offset++];
  if (first == 0 || first == 0xff) return false;
  uint32_t tag = first;
  if ((first & 31) == 31) {
    unsigned count = 0; uint8_t b;
    do { if (offset >= size || ++count > 2) return false;
      b = data[offset++]; tag = (tag << 8) | b;
    } while (b & 128);
  }
  if (offset >= size) return false;
  size_t length = data[offset++];
  if (length & 128) {
    size_t bytes = length & 127; length = 0;
    if (!bytes || bytes > 2 || bytes > size-offset) return false;
    while (bytes--) length = (length << 8) | data[offset++];
  }
  if (length > size-offset) return false;
  out = {tag, data+offset, length, bool(first & 32)};
  offset += length; return true;
}
