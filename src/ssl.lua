------------------------------------------------------------------------------
-- LuaSec 0.7
--
-- Copyright (C) 2006-2018 Bruno Silvestre
--
------------------------------------------------------------------------------

local core    = require("ssl.core")
local context = require("ssl.context")

local unpack  = table.unpack or unpack

-- We must prevent the contexts to be collected before the connections,
-- otherwise the C registry will be cleared.
local registry = setmetatable({}, {__mode="k"})

--
--
--
local function optexec(func, param, ctx)
  if param then
    if type(param) == "table" then
      return func(ctx, unpack(param))
    else
      return func(ctx, param)
    end
  end
  return true
end

--
--
--
local function newcontext(cfg)
   local succ, msg, ctx
   -- Create the context
   ctx, msg = context.create()
   if not ctx then return nil, msg end
   -- Mode
   succ, msg = context.setmode(ctx, cfg.mode)
   if not succ then return nil, msg end
   -- Protocol
   succ, msg = context.setprotocol(ctx, cfg.protocol)
   if not succ then return nil, msg end
   -- Load the key
   if cfg.key then
      succ, msg = context.loadkey(ctx, cfg.key)
      if not succ then return nil, msg end
   end
   -- Load the certificate
   if cfg.certificate then
     succ, msg = context.loadcert(ctx, cfg.certificate)
     if not succ then return nil, msg end
     if cfg.key and context.checkkey then
       succ = context.checkkey(ctx)
       if not succ then return nil, "private key does not match public key" end
     end
   end
   -- Load the CA certificates
   if cfg.cafile or cfg.capath then
      succ, msg = context.locations(ctx, cfg.cafile, cfg.capath)
      if not succ then return nil, msg end
   end
   -- Set SSL ciphers
   if cfg.ciphers then
      succ, msg = context.setcipher(ctx, cfg.ciphers)
      if not succ then return nil, msg end
   end
   -- Set the verification options
   succ, msg = optexec(context.setverify, cfg.verify, ctx)
   if not succ then return nil, msg end
   -- Set SSL options
   succ, msg = optexec(context.setoptions, cfg.options, ctx)
   if not succ then return nil, msg end
   -- Set the depth for certificate verification
   if cfg.depth then
      succ, msg = context.setdepth(ctx, cfg.depth)
      if not succ then return nil, msg end
   end

   return ctx
end

--
--
--
local function wrap(sock, cfg)
   local ctx, msg
   if type(cfg) == "table" then
      ctx, msg = newcontext(cfg)
      if not ctx then return nil, msg end
   else
      ctx = cfg
   end
   local s, msg = core.create(ctx)
   if s then
      core.setfd(s, sock:getfd())
      sock:setfd(core.SOCKET_INVALID)
      registry[s] = ctx
      return s
   end
   return nil, msg 
end

--------------------------------------------------------------------------------
-- Export module
--

local _M = {
  _VERSION        = "0.7",
  _COPYRIGHT      = core.copyright(),
  newcontext      = newcontext,
  wrap            = wrap,
}

return _M
