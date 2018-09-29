#ifndef LSEC_OPTIONS_H
#define LSEC_OPTIONS_H

/*--------------------------------------------------------------------------
 * LuaSec 0.7
 *
 * Copyright (C) 2006-2018 Bruno Silvestre
 *
 *--------------------------------------------------------------------------*/

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

/* If you need to generate these options again, see options.lua */

/* 
  OpenSSL version: WolfSSL 3.15.3
*/

struct ssl_option_s {
  const char *name;
  unsigned long code;
};
typedef struct ssl_option_s ssl_option_t;

static ssl_option_t ssl_options[] = {
  {"no_sslv2", WOLFSSL_OP_NO_SSLv2},
  {NULL, 0L}
};

#endif

