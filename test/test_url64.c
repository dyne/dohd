/* dohd test unit for url64 decoding
 *
 * Copyright (C) 2022 Dyne.org foundation
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

extern int dohd_url64_decode(const char *src, uint8_t *dest, uint32_t *dest_len);

static const int32_t hextable[] = {
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1, 0,1,2,3,4,5,6,7,8,9,-1,-1,-1,-1,-1,-1,-1,10,11,12,13,14,15,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,10,11,12,13,14,15,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

// takes zero terminated hex string, requires pre-allocation of dst,
// returns len in bytes
static int hex2buf(char *dst, const char *hex) {
  register int i, j;
  for(i=0, j=0; hex[j]!=0; i++, j+=2)
    dst[i] = (hextable[(short)hex[j]]<<4) + hextable[(short)hex[j+1]];
  return(i);
}

// takes binary buffer and its bytes length, requires pre-allocation
// of dst string
static const char hexes[] = "0123456789abcdef";
static void buf2hex(char *dst, const uint8_t *buf, const size_t len) {
  register size_t i;
  register unsigned char ch;
  for (i=0; i<len; i++) {
    ch=buf[i];
    dst[i<<1]     = hexes[ch>>4];
    dst[(i<<1)+1] = hexes[ch & 0xf];
  }
  dst[len<<1] = 0x0; // null termination
}

static int test_compare(const char *url64, const char *hex) {
  uint32_t out_len = 128;
  uint8_t out_bin[128];
  char out_hex[256];
  int check_len = strlen(hex) / 2;
  fprintf(stderr,"%u %s\n",check_len, hex);
  char *check_bin = calloc(check_len+1, 1);
  hex2buf(check_bin, hex);
  dohd_url64_decode(url64, out_bin, &out_len);
  if(out_len != check_len) return(0);
  if(memcmp(check_bin, out_bin, check_len) !=0) return(0);
  buf2hex(out_hex, out_bin, out_len);
  fprintf(stderr,"%u %s\n",out_len, out_hex);
  return(1);
}

int main(int argc, char **argv) {
  (void)argc;
  (void)argv;
  fprintf(stderr,"TEST URL64\n");
  const char *test1 =
    "AAABAAABAAAAAAABBG9jc3AIZGlnaWNlcnQDY29tAAABAAEAACkQAAAAAAAAUgAIAAQAAQAAAAwARg";
  const char *test1_hex =
    "000001000001000000000001046f63737008646967696365727403636f6d000001000100002910000000000000520008000400010000000c0046";
  if( ! test_compare(test1, test1_hex) ) exit(1);

  const char *test2 = "AAABAAABAAAAAAABB2V4YW1wbGUDY29tAAACAAEAACkQAAAAAAAAWAAIAAQAAQAAAAwATAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const char *test2_hex = "000001000001000000000001076578616d706c6503636f6d000002000100002910000000000000580008000400010000000c004c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

  if(! test_compare(test2, test2_hex) ) exit(1);

  exit(0);
}
