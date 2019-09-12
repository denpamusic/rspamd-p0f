
local tcp = require "rspamd_tcp"
local rspamd_util = require "rspamd_util"
local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local lua_util = require "lua_util"

-- SEE: https://github.com/p0f/p0f/blob/v3.06b/docs/README#L317
local S = {
  BAD_QUERY = 0x0,
  OK        = 0x10,
  NO_MATCH  = 0x20
}
local N = 'p0f'

if confighelp then
  rspamd_config:add_example(nil, N,
    'Detect remote OS via passive fingerprinting',
    [[
p0f {
  # Path to the unix socket that p0f listens on
  socket = '/tmp/p0f.sock';

  # Connection timeout
  timeout = 10;

  # If defined, insert symbol with lookup results
  symbol = 'P0F';

  # If defined, insert header with lookup results with following format
  # format "$OS (up: $UPTIME min), (distance $DISTANCE, link: $LINK), [$IP]"
  header = false;

  # Patterns to match OS string against
  patterns = {
    WINDOWS = '^Windows.*';
  }
}
]])
  return
end

local settings = {
  socket = '/tmp/p0f.sock',
  timeout = 10,
  header = false,
  symbol = 'P0F',
  patterns = {}
}

local templates = {
   hdr = '$OS (up: $UPTIME min), (distance $DISTANCE, link: $LINK), [$IP]',
   res = 'os: $OS, uptime: $UPTIME min, distance: $DISTANCE, link: $LINK'
}

local function ip2bin(ip)
  local addr = ip:to_table()

  for k, v in ipairs(addr) do
    addr[k] = rspamd_util.pack('B', v)
  end

  return table.concat(addr)
end

local function trim(...)
  local vars = {...}

  for k, v in ipairs(vars) do
    -- skip numbers, trim only strings
    if tonumber(vars[k]) == nil then
    	vars[k] = string.gsub(vars[k], '[^%w-_\\.\\(\\) ]', '')
    end
  end

  return lua_util.unpack(vars)
end

local function check_p0f(task)

  local function get_header(result)
     return rspamd_util.fold_header(settings.header,
      lua_util.template(templates.hdr, result))
  end

  local function add_p0f(result)
    task:get_mempool():set_variable('os', result.OS)

    for sym, r in pairs(settings.patterns) do
      if rspamd_regexp.create_cached(r):match(result.OS) then
        rspamd_logger.infox(task, 'matched pattern for rule %s', sym)
        task:insert_result(sym, 1.0)
      end
    end

    if settings.header then
      task:set_milter_reply({
        add_headers = { [settings.header] = get_header(result) }
      })
    end

    if settings.symbol then
      task:insert_result(settings.symbol, 0.0,
        lua_util.template(templates.res, result))
    end
  end

  local function check_p0f_cb(err, data)
    --[[
      p0f_api_response: magic, status, first_seen, last_seen, total_conn,
      uptime_min, up_mod_days, last_nat, last_chg, distance, bad_sw, os_match_q,
      os_name, os_flavor, http_name, http_flavor, link_type, language
    ]]--

    local _, status, _, _, _, uptime_min, _, _, _, distance, _, _, os_name,
      os_flavor, _, _, link_type, _ = trim(rspamd_util.unpack(
        'I4I4I4I4I4I4I4II4i1I1I1c32c32c32c32c32c32', tostring(data)))

      if status ~= S.OK then
        if status == S.BAD_QUERY then
          rspamd_logger.errx(task, 'malformed p0f query on %s', settings.socket)
        end
        return
      end

      add_p0f({
        OS = #os_name ~= 0 and (os_name .. ' ' .. os_flavor) or 'unknown',
        UPTIME = uptime_min,
        DISTANCE = distance,
        LINK = link_type,
        IP = tostring(task:get_from_ip())
      })
  end

  local ip = task:get_from_ip()

  if not (ip and ip:is_valid()) or ip:is_local() then
    return
  end

  local query = rspamd_util.pack('I4 I1 c16', 0x50304601,
    ip:get_version(), ip2bin(ip))

  tcp.request({
    host = settings.socket,
    callback = check_p0f_cb,
    data = { query },
    task = task,
    timeout = settings.timeout
  })
end

local id = rspamd_config:register_symbol({
  name = 'P0F_CHECK',
  type = 'prefilter,nostat',
  callback = check_p0f,
  priority = 8,
  flags = 'empty',
  group = N
})

if settings.symbol then
  rspamd_config:register_symbol({
    name = settings.symbol,
    parent = id,
    type = 'virtual',
    flags = 'empty',
    group = N
  })
end

local opts = rspamd_config:get_all_opt(N)

if opts then
  settings = lua_util.override_defaults(settings, opts)

  for sym in pairs(settings.patterns) do
    rspamd_logger.debugm(N, rspamd_config, 'registering: %1', {
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
    rspamd_config:register_symbol({
      type = 'virtual',
      name = sym,
      parent = id,
      group = N
    })
  end
end
