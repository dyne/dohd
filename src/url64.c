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
#include <limits.h>
#include <stddef.h>

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

static size_t dohd_url64_declen_size(size_t len)
{
    return ((len + 3U) >> 2) * 3U;
}

int dohd_url64_check(const char *in, size_t in_len) {
    size_t c;
    const unsigned char *bufin;

    if (!in || in_len > (size_t)INT_MAX)
        return 0;
    bufin = (const unsigned char *)in;
    for (c = 0; c < in_len; c++) {
        if (asciitable[bufin[c]] > 63)
            return 0;
    }
    return (int)in_len;
}

int dohd_url64_decode(const char *src, size_t src_len, uint8_t *dest, size_t dest_cap) {
    const unsigned char *bufin;
    unsigned char *bufout;
    size_t nprbytes;
    const unsigned char *_buf = (const unsigned char *) src;
    size_t out_cap;

    if (!src || !dest || dest_cap == 0)
        return -1;
    if (src_len > (size_t)INT_MAX)
        return -1;
    if (dohd_url64_check(src, src_len) != (int)src_len)
        return -1;
    if (dohd_url64_declen_size(src_len) + 1 > dest_cap)
        return -1;

    bufin = _buf;
    nprbytes = src_len;
    out_cap = dest_cap - 1;
    bufout = (unsigned char *) dest;
    bufin = _buf;

    while (nprbytes > 4) {
        if (out_cap < 3)
            return -1;
        *(bufout++) = (unsigned char) (asciitable[*bufin] << 2 | asciitable[bufin[1]] >> 4);
        *(bufout++) = (unsigned char) (asciitable[bufin[1]] << 4 | asciitable[bufin[2]] >> 2);
        *(bufout++) = (unsigned char) (asciitable[bufin[2]] << 6 | asciitable[bufin[3]]);
        bufin += 4;
        nprbytes -= 4;
        out_cap -= 3;
    }

    if (nprbytes > 1) {
        if (out_cap < 1)
            return -1;
        *(bufout++) = (unsigned char) (asciitable[*bufin] << 2 | asciitable[bufin[1]] >> 4);
        out_cap--;
    }
    if (nprbytes > 2) {
        if (out_cap < 1)
            return -1;
        *(bufout++) = (unsigned char) (asciitable[bufin[1]] << 4 | asciitable[bufin[2]] >> 2);
        out_cap--;
    }
    if (nprbytes > 3) {
        if (out_cap < 1)
            return -1;
        *(bufout++) = (unsigned char) (asciitable[bufin[2]] << 6 | asciitable[bufin[3]]);
    }

    *(bufout++) = '\0';
    return (int)(bufout - (unsigned char *)dest - 1);
}
