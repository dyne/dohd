/*
 *      url64.h
 *
 * dohd url64 decoding
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
 */

#ifndef URL64_H_INCLUDED
#define URL64_H_INCLUDED
#include <stddef.h>
#include <stdint.h>

int dohd_url64_declen(int len);
int dohd_url64_decode(const char *src, size_t src_len, uint8_t *dest, size_t dest_cap);
int dohd_url64_check(const char *in, size_t in_len);
#endif
