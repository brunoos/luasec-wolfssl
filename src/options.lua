local function usage()
  print("Usage:")
  print("* Generate options of your system:")
  print("  lua options.lua -g /path/to/ssl.h [version] > options.h")
  print("* Examples:")
  print("  lua options.lua -g /usr/include/wolfssl/ssl.h > options.h\n")
  print("  lua options.lua -g /usr/include/wolfssl/ssl.h \"WolfSSL 3.15.3\" > options.h\n")

  print("* List options of your system:")
  print("  lua options.lua -l /path/to/ssl.h\n")
end

--
local function printf(str, ...)
  print(string.format(str, ...))
end

local function generate(options, version)
  print([[
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
]])
  printf([[
/* 
  OpenSSL version: %s
*/
]], version)
  print([[
struct ssl_option_s {
  const char *name;
  unsigned long code;
};
typedef struct ssl_option_s ssl_option_t;
]])

  print([[static ssl_option_t ssl_options[] = {]])

  for k, option in ipairs(options) do
    local name = string.lower(string.match(option, "WOLFSSL_OP_(%S+)"))
    print(string.format([[  {"%s", %s},]], name, option))
  end
  print([[  {NULL, 0L}]])
  print([[
};

#endif
]])
end

local function loadoptions(file)
  local options = {}
  local f = assert(io.open(file, "r"))
  for line in f:lines() do
    --local op = string.match(line, "define%s+(SSL_OP_%S+)")
    local op = string.match(line, "^%s+(WOLFSSL_OP_%S+)%s+=")
    if op then
      table.insert(options, op)
    end
  end
  table.sort(options, function(a,b) return a<b end)
  return options
end
--

local options
local flag, file, version = ...

version = version or "Unknown"

if not file then
  usage()
elseif flag == "-g" then
  options = loadoptions(file)
  generate(options, version)
elseif flag == "-l" then
  options = loadoptions(file)
  for k, option in ipairs(options) do
    print(option)
  end
else
  usage()
end
