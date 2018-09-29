/*--------------------------------------------------------------------------
 * LuaSec 0.7
 *
 * Copyright (C) 2006-2018 Bruno Silvestre.
 *
 *--------------------------------------------------------------------------*/

#include <errno.h>
#include <string.h>

#if defined(WIN32)
#include <winsock2.h>
#endif

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <lua.h>
#include <lauxlib.h>

#include <luasocket/io.h>
#include <luasocket/buffer.h>
#include <luasocket/timeout.h>
#include <luasocket/socket.h>

#include "context.h"
#include "ssl.h"


/**
 * Map error code into string.
 */
static const char *ssl_ioerror(void *ctx, int err)
{
  if (err == LSEC_IO_SSL) {
    p_ssl ssl = (p_ssl) ctx;
    switch(ssl->error) {
    case SSL_ERROR_NONE:        return "No error";
    case SSL_ERROR_WANT_READ:   return "wantread";
    case SSL_ERROR_WANT_WRITE:  return "wantwrite";
    case ZERO_RETURN:
    case SOCKET_PEER_CLOSED_E:
    case SOCKET_ERROR_E:        return "closed";
    default:                    return wolfSSL_ERR_reason_error_string(ssl->error);
    }
  }
  return socket_strerror(err);
}

/**
 * Close the connection before the GC collect the object.
 */
static int meth_destroy(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state == LSEC_STATE_CONNECTED) {
    socket_setblocking(&ssl->sock);
    wolfSSL_shutdown(ssl->ssl);
  }
  if (ssl->sock != SOCKET_INVALID) {
    socket_destroy(&ssl->sock);
  }
  ssl->state = LSEC_STATE_CLOSED;
  if (ssl->ssl) {
    wolfSSL_free(ssl->ssl);
    ssl->ssl = NULL;
  }
  return 0;
}

/**
 * Perform the TLS/SSL handshake
 */
static int handshake(p_ssl ssl)
{
  int err;
  p_timeout tm = timeout_markstart(&ssl->tm);
  if (ssl->state == LSEC_STATE_CLOSED)
    return IO_CLOSED;
  for ( ; ; ) {
    wolfSSL_ERR_clear_error();
    if (wolfSSL_is_server(ssl->ssl))
      err = wolfSSL_accept(ssl->ssl);
    else
      err = wolfSSL_connect(ssl->ssl);
    if (err == SSL_SUCCESS) {
      ssl->state = LSEC_STATE_CONNECTED;
      return IO_DONE;
    }
    ssl->error = wolfSSL_get_error(ssl->ssl, err);
    switch (ssl->error) {
    case SSL_ERROR_WANT_READ:
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    default:
      return LSEC_IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Send data
 */
static int ssl_send(void *ctx, const char *data, size_t count, size_t *sent, p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl)ctx;
  if (ssl->state != LSEC_STATE_CONNECTED)
    return IO_CLOSED;
  *sent = 0;
  for ( ; ; ) {
    wolfSSL_ERR_clear_error();
    err = wolfSSL_write(ssl->ssl, data, (int)count);
    ssl->error = wolfSSL_get_error(ssl->ssl, err);
    switch (ssl->error) {
    case SSL_ERROR_NONE:
      *sent = err;
      return IO_DONE;
    case SSL_ERROR_WANT_READ: 
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    default:
      return LSEC_IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Receive data
 */
static int ssl_recv(void *ctx, char *data, size_t count, size_t *got, p_timeout tm)
{
  int err;
  p_ssl ssl = (p_ssl)ctx;
  *got = 0;
  if (ssl->state != LSEC_STATE_CONNECTED)
    return IO_CLOSED;
  for ( ; ; ) {
    wolfSSL_ERR_clear_error();
    err = wolfSSL_read(ssl->ssl, data, (int)count);
    ssl->error = wolfSSL_get_error(ssl->ssl, err);
    switch (ssl->error) {
    case SSL_ERROR_NONE:
      *got = err;
      return IO_DONE;
    case SSL_ERROR_WANT_READ:
      err = socket_waitfd(&ssl->sock, WAITFD_R, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    case SSL_ERROR_WANT_WRITE:
      err = socket_waitfd(&ssl->sock, WAITFD_W, tm);
      if (err == IO_TIMEOUT) return LSEC_IO_SSL;
      if (err != IO_DONE)    return err;
      break;
    default:
      return LSEC_IO_SSL;
    }
  }
  return IO_UNKNOWN;
}

/**
 * Create a new TLS/SSL object and mark it as new.
 */
static int meth_create(lua_State *L)
{
  p_ssl ssl;
  int mode;
  WOLFSSL_CTX *ctx;

  lua_settop(L, 1);

  ssl = (p_ssl)lua_newuserdata(L, sizeof(t_ssl));
  if (!ssl) {
    lua_pushnil(L);
    lua_pushstring(L, "error creating SSL object");
    return 2;
  }

  if ((ctx = lsec_testcontext(L, 1))) {
    mode = lsec_getmode(L, 1);
    if (mode == LSEC_MODE_INVALID) {
      lua_pushnil(L);
      lua_pushstring(L, "invalid mode");
      return 2;
    }
    ssl->ssl = wolfSSL_new(ctx);
    if (!ssl->ssl) {
      lua_pushnil(L);
      lua_pushfstring(L, "error creating SSL object (%s)", wolfSSL_ERR_reason_error_string(wolfSSL_ERR_get_error()));
      return 2;
    }
  }
  else {
    return luaL_argerror(L, 1, "invalid context");
  }

  ssl->state = LSEC_STATE_NEW;
  wolfSSL_set_fd(ssl->ssl, (int)SOCKET_INVALID);

  io_init(&ssl->io, (p_send)ssl_send, (p_recv)ssl_recv, (p_error) ssl_ioerror, ssl);
  timeout_init(&ssl->tm, -1, -1);
  buffer_init(&ssl->buf, &ssl->io, &ssl->tm);

  luaL_getmetatable(L, "SSL:Connection");
  lua_setmetatable(L, -2);

  return 1;
}

/**
 * Buffer send function
 */
static int meth_send(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_send(L, &ssl->buf);
}

/**
 * Buffer receive function
 */
static int meth_receive(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_receive(L, &ssl->buf);
}

/**
 * Get the buffer's statistics.
 */
static int meth_getstats(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_getstats(L, &ssl->buf);
}

/**
 * Set the buffer's statistics.
 */
static int meth_setstats(lua_State *L) {
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return buffer_meth_setstats(L, &ssl->buf);
}

/**
 * Select support methods
 */
static int meth_getfd(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushnumber(L, ssl->sock);
  return 1;
}

/**
 * Set the TLS/SSL file descriptor.
 * Call it *before* the handshake.
 */
static int meth_setfd(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != LSEC_STATE_NEW)
    luaL_argerror(L, 1, "invalid SSL object state");
  ssl->sock = (t_socket)luaL_checkinteger(L, 2);
  socket_setnonblocking(&ssl->sock);
  wolfSSL_set_fd(ssl->ssl, (int)ssl->sock);
  return 0;
}

/**
 * Lua handshake function.
 */
static int meth_handshake(lua_State *L)
{
  int err;
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  err = handshake(ssl);
  if (err == IO_DONE) {
    lua_pushboolean(L, 1);
    return 1;
  }
  lua_pushboolean(L, 0);
  lua_pushstring(L, ssl_ioerror((void*)ssl, err));
  return 2;
}

/**
 * Close the connection.
 */
static int meth_close(lua_State *L)
{
  meth_destroy(L);
  return 0;
}

/**
 * Set timeout.
 */
static int meth_settimeout(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  return timeout_meth_settimeout(L, &ssl->tm);
}

/**
 * Check if there is data in the buffer.
 */
static int meth_dirty(lua_State *L)
{
  int res = 0;
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state != LSEC_STATE_CLOSED)
    res = !buffer_isempty(&ssl->buf) || wolfSSL_pending(ssl->ssl);
  lua_pushboolean(L, res);
  return 1;
}

/**
 * Return the state information about the SSL object.
 */
static int meth_want(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  if (ssl->state == LSEC_STATE_CLOSED) {
    lua_pushstring(L, "nothing");
  } else if (wolfSSL_want_read(ssl->ssl)) {
    lua_pushstring(L, "read");
  } else if (wolfSSL_want_write(ssl->ssl)) {
    lua_pushstring(L, "write");
  } else {
    lua_pushstring(L, "nothing");
  }
  return 1;
}

/**
 * Object information -- tostring metamethod
 */
static int meth_tostring(lua_State *L)
{
  p_ssl ssl = (p_ssl)luaL_checkudata(L, 1, "SSL:Connection");
  lua_pushfstring(L, "SSL connection: %p%s", ssl,
    ssl->state == LSEC_STATE_CLOSED ? " (closed)" : "");
  return 1;
}

static int meth_copyright(lua_State *L)
{
  lua_pushstring(L, "LuaSec 0.7 - Copyright (C) 2006-2018 Bruno Silvestre, UFG"
#if defined(WITH_LUASOCKET)
                    "\nLuaSocket 3.0-RC1 - Copyright (C) 2004-2013 Diego Nehab"
#endif
  );
  return 1;
}

/*---------------------------------------------------------------------------*/

/**
 * SSL methods 
 */
static luaL_Reg methods[] = {
  {"close",               meth_close},
  {"getfd",               meth_getfd},
  {"getstats",            meth_getstats},
  {"setstats",            meth_setstats},
  {"dirty",               meth_dirty},
  {"dohandshake",         meth_handshake},
  {"receive",             meth_receive},
  {"send",                meth_send},
  {"settimeout",          meth_settimeout},
  {"want",                meth_want},
  {NULL,                  NULL}
};

/**
 * SSL metamethods.
 */
static luaL_Reg meta[] = {
  {"__gc",       meth_destroy},
  {"__tostring", meth_tostring},
  {NULL, NULL}
};

/**
 * SSL functions. 
 */
static luaL_Reg funcs[] = {
  {"create",      meth_create},
  {"setfd",       meth_setfd},
  {"copyright",   meth_copyright},
  {NULL,          NULL}
};

/**
 * Initialize modules.
 */
LSEC_API int luaopen_ssl_core(lua_State *L)
{
  /* Initialize SSL */
  if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
    lua_pushstring(L, "unable to initialize SSL library");
    lua_error(L);
  }

#if defined(WITH_LUASOCKET)
  /* Initialize internal library */
  socket_open();
#endif

  /* Register the functions and tables */
  luaL_newmetatable(L, "SSL:Connection");
  setfuncs(L, meta);

  luaL_newlib(L, methods);
  lua_setfield(L, -2, "__index");

  luaL_newlib(L, funcs);

  lua_pushstring(L, "SOCKET_INVALID");
  lua_pushnumber(L, SOCKET_INVALID);
  lua_rawset(L, -3);

  return 1;
}

//------------------------------------------------------------------------------

#if defined(_MSC_VER)

/* Empty implementation to allow building with LuaRocks and MS compilers */
LSEC_API int luaopen_ssl(lua_State *L) {
  lua_pushstring(L, "you should not call this function");
  lua_error(L);
  return 0;
}

#endif
