/*--------------------------------------------------------------------------
 * LuaSec 0.7
 *
 * Copyright (C) 2006-2018 Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include <string.h>

#if defined(WIN32)
#include <windows.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <lua.h>
#include <lauxlib.h>

#include "context.h"
#include "options.h"

/*--------------------------- Auxiliary Functions ----------------------------*/

/**
 * Return the context.
 */
static p_context checkctx(lua_State *L, int idx)
{
  return (p_context)luaL_checkudata(L, idx, "SSL:Context");
}

static p_context testctx(lua_State *L, int idx)
{
  return (p_context)luaL_testudata(L, idx, "SSL:Context");
}

/**
 * Prepare the SSL options flag.
 */
static int set_option_flag(const char *opt, unsigned long *flag)
{
  ssl_option_t *p;
  for (p = ssl_options; p->name; p++) {
    if (!strcmp(opt, p->name)) {
      *flag |= p->code;
      return 1;
    }
  }
  return 0;
}

/**
 * Find the protocol.
 */
static WOLFSSL_METHOD* str2method(const char *method, int mode)
{
  if (mode == LSEC_MODE_SERVER) {
    if (!strcmp(method, "any"))     return wolfSSLv23_server_method();
    if (!strcmp(method, "tlsv1_1")) return wolfTLSv1_1_server_method();
    if (!strcmp(method, "tlsv1_2")) return wolfTLSv1_2_server_method();
  }
  if (mode == LSEC_MODE_CLIENT) {
    if (!strcmp(method, "any"))     return wolfSSLv23_client_method();
    if (!strcmp(method, "tlsv1_1")) return wolfTLSv1_1_client_method();
    if (!strcmp(method, "tlsv1_2")) return wolfTLSv1_2_client_method();
  }
  return NULL;
}

/**
 * Prepare the SSL handshake verify flag.
 */
static int set_verify_flag(const char *str, int *flag)
{
  if (!strcmp(str, "none")) { 
    *flag |= SSL_VERIFY_NONE;
    return 1;
  }
  if (!strcmp(str, "peer")) {
    *flag |= SSL_VERIFY_PEER;
    return 1;
  }
  if (!strcmp(str, "client_once")) {
    *flag |= SSL_VERIFY_CLIENT_ONCE;
    return 1;
  }
  if (!strcmp(str, "fail_if_no_peer_cert")) { 
    *flag |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    return 1;
  }
  return 0;
}

/*------------------------------ Lua Functions -------------------------------*/

/**
 * Create a SSL context.
 */
static int create(lua_State *L)
{
  p_context ctx = (p_context) lua_newuserdata(L, sizeof(t_context));
  if (!ctx) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating context");
    return 2;
  }
  memset(ctx, 0, sizeof(t_context));
  ctx->mode = LSEC_MODE_INVALID;
  luaL_getmetatable(L, "SSL:Context");
  lua_setmetatable(L, -2);
  return 1;
}

static int set_protocol(lua_State *L)
{
  p_context ctx;
  const char *str_method;
  WOLFSSL_METHOD *method;

  ctx = checkctx(L, 1);
  str_method = luaL_checkstring(L, 2);
  method = str2method(str_method, ctx->mode);
  if (!method) {
    lua_pushnil(L);
    lua_pushfstring(L, "invalid protocol (%s)", str_method);
    return 2;
  }
  ctx->context = wolfSSL_CTX_new(method);
  if (!ctx->context) {
    lua_pushnil(L);
    wolfSSL_ERR_get_error();
    lua_pushfstring(L, "error creating context (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
    return 2;
  }
  wolfSSL_CTX_set_mode(ctx->context, SSL_MODE_ENABLE_PARTIAL_WRITE);
  wolfSSL_CTX_set_mode(ctx->context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
  /* No session support */
  wolfSSL_CTX_set_session_cache_mode(ctx->context, SSL_SESS_CACHE_OFF);
  /* Link LuaSec context with the OpenSSL context */
  wolfSSL_CTX_set_ex_data(ctx->context, 0, ctx);
  return 1;
}

/**
 * Load the trusting certificates.
 */
static int load_locations(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  const char *cafile = luaL_optstring(L, 2, NULL);
  const char *capath = luaL_optstring(L, 3, NULL);
  if (wolfSSL_CTX_load_verify_locations(ctx, cafile, capath) != WOLFSSL_SUCCESS) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error loading CA locations (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Load the certificate file.
 */
static int load_cert(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  const char *filename = luaL_checkstring(L, 2);
  if (wolfSSL_CTX_use_certificate_chain_file(ctx, filename) != WOLFSSL_SUCCESS) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error loading certificate (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Load the key file -- only in PEM format.
 */
static int load_key(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  const char *filename = luaL_checkstring(L, 2);
  if (wolfSSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM) != WOLFSSL_SUCCESS) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error loading private key (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Check that the certificate public key matches the private key
 */

static int check_key(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  lua_pushboolean(L, wolfSSL_CTX_check_private_key(ctx));
  return 1;
}

/**
 * Set the cipher list.
 */
static int set_cipher(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  const char *list = luaL_checkstring(L, 2);
  if (wolfSSL_CTX_set_cipher_list(ctx, list) != WOLFSSL_SUCCESS) {
    lua_pushboolean(L, 0);
    lua_pushfstring(L, "error setting cipher list (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
    return 2;
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the depth for certificate checking.
 */
static int set_depth(lua_State *L)
{
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  wolfSSL_CTX_set_verify_depth(ctx, (int)luaL_checkinteger(L, 2));
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the handshake verify options.
 */
static int set_verify(lua_State *L)
{
  int i;
  const char *str;
  int flag = 0;
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  int max = lua_gettop(L);
  for (i = 2; i <= max; i++) {
    str = luaL_checkstring(L, i);
    if (!set_verify_flag(str, &flag)) {
      lua_pushboolean(L, 0);
      lua_pushfstring(L, "invalid verify option (%s)", str);
      return 2;
    }
  }
  if (flag) wolfSSL_CTX_set_verify(ctx, flag, NULL);
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the protocol options.
 */
static int set_options(lua_State *L)
{
  int i;
  const char *str;
  unsigned long flag = 0L;
  WOLFSSL_CTX *ctx = lsec_checkcontext(L, 1);
  int max = lua_gettop(L);
  /* any option? */
  if (max > 1) {
    for (i = 2; i <= max; i++) {
      str = luaL_checkstring(L, i);
      if (!set_option_flag(str, &flag)) {
        lua_pushboolean(L, 0);
        lua_pushfstring(L, "invalid option (%s)", str);
        return 2;
      }
    }
    wolfSSL_CTX_set_options(ctx, flag);
  }
  lua_pushboolean(L, 1);
  return 1;
}

/**
 * Set the context mode.
 */
static int set_mode(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  const char *str = luaL_checkstring(L, 2);
  if (!strcmp("server", str)) {
    ctx->mode = LSEC_MODE_SERVER;
    lua_pushboolean(L, 1);
    return 1;
  }
  if (!strcmp("client", str)) {
    ctx->mode = LSEC_MODE_CLIENT;
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  lua_pushfstring(L, "invalid mode (%s)", str);
  return 1;
}   

/**
 * Package functions
 */
static luaL_Reg funcs[] = {
  {"create",       create},
  {"locations",    load_locations},
  {"loadcert",     load_cert},
  {"loadkey",      load_key},
  {"checkkey",     check_key},
  {"setcipher",    set_cipher},
  {"setdepth",     set_depth},
  {"setprotocol",  set_protocol},
  {"setverify",    set_verify},
  {"setoptions",   set_options},
  {"setmode",      set_mode},
  {NULL,           NULL}
};

/*-------------------------------- Metamethods -------------------------------*/

/**
 * Collect SSL context -- GC metamethod.
 */
static int meth_destroy(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  if (ctx->context) {
    wolfSSL_CTX_free(ctx->context);
    ctx->context = NULL;
  }
  return 0;
}

/**
 * Object information -- tostring metamethod.
 */
static int meth_tostring(lua_State *L)
{
  p_context ctx = checkctx(L, 1);
  lua_pushfstring(L, "SSL context: %p", ctx);
  return 1;
}

/**
 * Context metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};

/*----------------------------- Public Functions  ---------------------------*/

/**
 * Retrieve the SSL context from the Lua stack.
 */
WOLFSSL_CTX* lsec_checkcontext(lua_State *L, int idx)
{
  p_context ctx = checkctx(L, idx);
  return ctx->context;
}

WOLFSSL_CTX* lsec_testcontext(lua_State *L, int idx)
{
  p_context ctx = testctx(L, idx);
  return (ctx) ? ctx->context : NULL;
}

/**
 * Retrieve the mode from the context in the Lua stack.
 */
int lsec_getmode(lua_State *L, int idx)
{
  p_context ctx = checkctx(L, idx);
  return ctx->mode;
}

/*-- Compat - Lua 5.1 --*/
#if (LUA_VERSION_NUM == 501)

void *lsec_testudata (lua_State *L, int ud, const char *tname) {
  void *p = lua_touserdata(L, ud);
  if (p != NULL) {  /* value is a userdata? */
    if (lua_getmetatable(L, ud)) {  /* does it have a metatable? */
      luaL_getmetatable(L, tname);  /* get correct metatable */
      if (!lua_rawequal(L, -1, -2))  /* not the same? */
        p = NULL;  /* value is a userdata with wrong metatable */
      lua_pop(L, 2);  /* remove both metatables */
      return p;
    }
  }
  return NULL;  /* value is not a userdata with a metatable */
}

#endif

/*------------------------------ Initialization ------------------------------*/

/**
 * Registre the module.
 */
LSEC_API int luaopen_ssl_context(lua_State *L)
{
  luaL_newmetatable(L, "SSL:Context");
  setfuncs(L, meta);

  luaL_newlib(L, funcs);

  return 1;
}
