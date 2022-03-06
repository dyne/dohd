/* dohd url64 decoding
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

#include <inttypes.h>

static const unsigned char asciitable[256] = {
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 63,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

// returns an estimation of the length of the data once decoded
int dohd_url64_declen(int len) { return ((len + 3) >> 2) * 3; }

// assumes null terminated string
// no padding equals check (no modulo 4)
// returns 0 if not base else length of base encoded string
int dohd_url64_check(const char *in) {
    if(!in) { return 0; }
    register int c;
    unsigned char *bufin;
    bufin = (unsigned char *)in;
    for(c=0; bufin[c] != '\0'; c++)
        if(asciitable[*(bufin+c)] > 63)
            return 0;
    return(c);
}

int dohd_url64_decode(const char *src, uint8_t *dest) {
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;
    const unsigned char *_buf = (const unsigned char *) src;
    bufin = _buf;
    while (asciitable[*(bufin++)] <= 63);
    nprbytes = bufin - _buf - 1;

    bufout = (unsigned char *) dest;
    bufin = _buf;

    while (nprbytes > 4) {
        *(bufout++) = (unsigned char) (asciitable[*bufin] << 2 | asciitable[bufin[1]] >> 4);
        *(bufout++) = (unsigned char) (asciitable[bufin[1]] << 4 | asciitable[bufin[2]] >> 2);
        *(bufout++) = (unsigned char) (asciitable[bufin[2]] << 6 | asciitable[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
    }

    if (nprbytes > 1)
        *(bufout++) = (unsigned char) (asciitable[*bufin] << 2 | asciitable[bufin[1]] >> 4);
    if (nprbytes > 2)
        *(bufout++) = (unsigned char) (asciitable[bufin[1]] << 4 | asciitable[bufin[2]] >> 2);
    if (nprbytes > 3)
        *(bufout++) = (unsigned char) (asciitable[bufin[2]] << 6 | asciitable[bufin[3]]);

    *(bufout++) = '\0';
    // return the length of decoded
    return(bufout-(unsigned char*)dest-1);
}
