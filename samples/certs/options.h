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
#include <wolfssl/openssl/ssl.h>

/* If you need to generate these options again, see options.lua */

/* 
  OpenSSL version: Unknown
*/

struct ssl_option_s {
  const char *name;
  unsigned long code;
};
typedef struct ssl_option_s ssl_option_t;

static ssl_option_t ssl_options[] = {
  {"all", SSL_OP_ALL},
  {"cipher_server_preference", SSL_OP_CIPHER_SERVER_PREFERENCE},
  {"cookie_exchange", SSL_OP_COOKIE_EXCHANGE},
  {"dont_insert_empty_fragments", SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS},
  {"ephemeral_rsa", SSL_OP_EPHEMERAL_RSA},
  {"microsoft_big_sslv3_buffer", SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER},
  {"microsoft_sess_id_bug", SSL_OP_MICROSOFT_SESS_ID_BUG},
  {"msie_sslv2_rsa_padding", SSL_OP_MSIE_SSLV2_RSA_PADDING},
  {"netscape_ca_dn_bug", SSL_OP_NETSCAPE_CA_DN_BUG},
  {"netscape_challenge_bug", SSL_OP_NETSCAPE_CHALLENGE_BUG},
  {"netscape_demo_cipher_change_bug", SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG},
  {"netscape_reuse_cipher_change_bug", SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG},
  {"no_compression", SSL_OP_NO_COMPRESSION},
  {"no_query_mtu", SSL_OP_NO_QUERY_MTU},
  {"no_session_resumption_on_renegotiation", SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION},
  {"no_sslv3", SSL_OP_NO_SSLv3},
  {"no_ticket", SSL_OP_NO_TICKET},
  {"no_tlsv1", SSL_OP_NO_TLSv1},
  {"no_tlsv1_1", SSL_OP_NO_TLSv1_1},
  {"no_tlsv1_2", SSL_OP_NO_TLSv1_2},
  {"no_tlsv1_3", SSL_OP_NO_TLSv1_3},
  {"pkcs1_check_1", SSL_OP_PKCS1_CHECK_1},
  {"pkcs1_check_2", SSL_OP_PKCS1_CHECK_2},
  {"single_dh_use", SSL_OP_SINGLE_DH_USE},
  {"single_ecdh_use", SSL_OP_SINGLE_ECDH_USE},
  {"ssleay_080_client_dh_bug", SSL_OP_SSLEAY_080_CLIENT_DH_BUG},
  {"sslref2_reuse_cert_type_bug", SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG},
  {"tls_block_padding_bug", SSL_OP_TLS_BLOCK_PADDING_BUG},
  {"tls_d5_bug", SSL_OP_TLS_D5_BUG},
  {"tls_rollback_bug", SSL_OP_TLS_ROLLBACK_BUG},
  {NULL, 0L}
};

#endif

