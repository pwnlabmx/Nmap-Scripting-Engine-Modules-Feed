local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local hl7 = require "hl7"

description = [[
Robustness (fuzz) tester for HL7 v2.x interface engines over MLLP.

Sends a series of malformed and abusive HL7 messages - bad MLLP framing, broken
MSH headers, wrong encoding characters, oversized fields, segment/field
injection payloads, and huge segment counts - and classifies how the engine
responds: accepted (MSA|AA), application error (MSA|AE), rejected (MSA|AR),
timeout/hang, connection reset, or an unparseable reply.

A well-formed baseline is sent first, and periodically re-sent as a health
check, so a case that hangs or crashes the engine is detected and the scan
halts with the offending case preserved.

This is an INTRUSIVE script that deliberately sends malformed data. It may
disrupt or crash a fragile interface engine. Only run it against systems you
are authorised to test, ideally in a lab or maintenance window.
]]

---
-- @usage
-- nmap -p2575 --script hl7-mllp-fuzzer <target>
-- @usage
-- nmap -p2575 --script hl7-mllp-fuzzer --script-args
--   hl7-mllp-fuzzer.timeout=5,hl7-mllp-fuzzer.health_interval=10 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-mllp-fuzzer:
-- |   Baseline: AA (Application Accept)
-- |   Cases sent: 18 / 18
-- |   Results: ACCEPT=6 ERROR=8 REJECT=2 TIMEOUT=1 RESET=1 CORRUPT=0
-- |   Notable:
-- |     [TIMEOUT] oversized_pid_1mb - engine did not respond within timeout
-- |_    [ACCEPT]  segment_injection_cr - engine accepted an injected segment
--
-- @args hl7-mllp-fuzzer.timeout  Per-case timeout in seconds. Default: 5
-- @args hl7-mllp-fuzzer.tls      Set to "true" for MLLP over TLS. Default:
--                                false
-- @args hl7-mllp-fuzzer.health_interval Re-send baseline every N cases (0 to
--                                       disable). Default: 6
-- @args hl7-mllp-fuzzer.sending_app     Sending Application (MSH-3). Default:
--                                       NMAP
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"fuzzer", "intrusive"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-mllp-fuzzer." .. name) or default
end

--- Build the list of fuzz cases. Each case is {id, desc, msg, raw, severity}.
-- If raw is true the msg bytes are sent without MLLP framing added.
local function build_cases(msh_opts)
  local baseline = hl7.build_qry_a19("1", msh_opts)
  local big = string.rep("A", 1024 * 1024)
  local enc = "^~\\&"
  local cases = {
    { id = "empty_message", severity = "low",
      desc = "empty message body", msg = "" },
    { id = "no_msh", severity = "medium",
      desc = "message without an MSH segment",
      msg = "PID|1||1||DOE^JOHN" },
    { id = "truncated_msh", severity = "medium",
      desc = "MSH truncated to 3 fields",
      msg = "MSH|" .. enc .. "|NMAP" },
    { id = "bad_encoding_chars", severity = "medium",
      desc = "MSH-2 encoding characters invalid",
      msg = "MSH|XXXX|NMAP|NMAP|||20240101||QRY^A19|1|P|2.5" },
    { id = "missing_field_separator", severity = "medium",
      desc = "MSH without a field separator",
      msg = "MSHZZZZ" },
    { id = "oversized_pid_1mb", severity = "high",
      desc = "PID-5 patient name of 1 MB",
      msg = hl7.build_message({
        hl7.build_msh(msh_opts),
        "PID|1||1||" .. big }) },
    { id = "segment_injection_cr", severity = "high",
      desc = "extra segment injected via embedded CR",
      msg = hl7.build_message({
        hl7.build_msh(msh_opts),
        "PID|1||1||DOE^JOHN",
        "ORC|NW|INJECTED^ORDER" }) },
    { id = "field_injection_pipe", severity = "high",
      desc = "unescaped field separators in PID name",
      msg = hl7.build_message({
        hl7.build_msh(msh_opts),
        "PID|1||1||A|B|C|D|E|F|G|H|I|J|K|L|M|N" }) },
    { id = "path_traversal_id", severity = "high",
      desc = "path traversal payload in patient id",
      msg = hl7.build_qry_a19("../../../../etc/passwd", msh_opts) },
    { id = "sqli_id", severity = "high",
      desc = "SQL injection payload in patient id",
      msg = hl7.build_qry_a19("1' OR '1'='1", msh_opts) },
    { id = "xss_id", severity = "high",
      desc = "XSS payload in patient id",
      msg = hl7.build_qry_a19("<script>alert(1)</script>", msh_opts) },
    { id = "null_byte_id", severity = "high",
      desc = "embedded NUL byte in patient id",
      msg = hl7.build_qry_a19("PAT\x00001", msh_opts) },
    { id = "huge_segment_count", severity = "high",
      desc = "message with 5000 OBX segments",
      msg = (function()
        local segs = { hl7.build_msh(msh_opts) }
        for i = 1, 5000 do
          segs[#segs + 1] = string.format("OBX|%d|ST|X||val", i)
        end
        return hl7.build_message(segs)
      end)() },
    { id = "bad_version", severity = "low",
      desc = "unknown HL7 version in MSH-12",
      msg = hl7.build_msh({ version = "9.9",
        message_type = "QRY^A19" }) },
    { id = "control_chars", severity = "medium",
      desc = "control characters in a field",
      msg = hl7.build_qry_a19("\x01\x02\x03\x1b", msh_opts) },
    { id = "no_vt_frame", severity = "medium", raw = true,
      desc = "MLLP frame missing the start block (VT)",
      msg = baseline .. hl7.MLLP.FS .. hl7.MLLP.CR },
    { id = "no_fs_frame", severity = "medium", raw = true,
      desc = "MLLP frame missing the end block (FS)",
      msg = hl7.MLLP.VT .. baseline },
    { id = "double_framed", severity = "low", raw = true,
      desc = "two MLLP frames in one send",
      msg = hl7.mllp_wrap(baseline) .. hl7.mllp_wrap(baseline) },
  }
  return cases, baseline
end

--- Send one case and classify the outcome.
-- @return class (string), detail (string)
local function run_case(host, port, case, timeout_s, tls)
  local sock = hl7.new_sock(timeout_s)
  local ok, err = hl7.connect(sock, host, port, tls)
  if not ok then
    sock:close()
    return "RESET", "connect failed: " .. tostring(err)
  end
  if case.raw then
    ok, err = sock:send(case.msg)
  else
    ok, err = hl7.send_message(sock, case.msg)
  end
  if not ok then
    sock:close()
    return "RESET", "send failed: " .. tostring(err)
  end
  local rok, resp = hl7.recv_message(sock)
  sock:close()
  if not rok then
    if resp == "TIMEOUT" then
      return "TIMEOUT", "no response within timeout"
    end
    return "RESET", tostring(resp)
  end
  local info = hl7.parse_response(resp)
  if not hl7.find_segment(info.segments, "MSH") then
    return "CORRUPT", "reply is not a parseable HL7 message"
  end
  local code = info.ack_code
  if code == "AA" or code == "CA" then
    return "ACCEPT", "MSA|" .. code
  elseif code == "AE" or code == "CE" then
    return "ERROR", "MSA|" .. code
  elseif code == "AR" or code == "CR" then
    return "REJECT", "MSA|" .. code
  end
  return "CORRUPT", "no MSA acknowledgement code"
end

--- Health check: send the baseline and confirm an accept.
local function health_ok(host, port, baseline, timeout_s, tls)
  local ok, resp = hl7.transact(host, port, baseline, timeout_s, tls)
  if not ok then return false end
  local info = hl7.parse_response(resp)
  return hl7.find_segment(info.segments, "MSH") ~= nil
end

action = function(host, port)
  local out = stdnse.output_table()
  local timeout_s = tonumber(arg("timeout", "5"))
  local health_int = tonumber(arg("health_interval", "6"))
  local tls = arg("tls", "false") == "true"
  local msh_opts = {
    sending_app = arg("sending_app", "NMAP"),
    sending_fac = arg("sending_fac", "NMAP"),
    processing_id = "T",
  }

  local cases, baseline = build_cases(msh_opts)

  -- Baseline
  local bok, bresp = hl7.transact(host, port, baseline, timeout_s, tls)
  if not bok then
    out["Baseline"] = "FAILED - no response to a well-formed message"
    out["Note"] = "Target may not speak HL7/MLLP: " .. tostring(bresp)
    return out
  end
  local binfo = hl7.parse_response(bresp)
  out["Baseline"] = string.format("%s (%s)",
    binfo.ack_code ~= "" and binfo.ack_code or "reply",
    binfo.ack_text ~= "" and binfo.ack_text or "no MSA")

  local tally = { ACCEPT = 0, ERROR = 0, REJECT = 0,
                  TIMEOUT = 0, RESET = 0, CORRUPT = 0 }
  local notable = {}
  local sent = 0
  local since_health = 0

  for _, case in ipairs(cases) do
    since_health = since_health + 1
    if health_int > 0 and since_health >= health_int then
      since_health = 0
      if not health_ok(host, port, baseline, timeout_s, tls) then
        notable[#notable + 1] = string.format(
          "[CRASH]   %s - baseline health check failed after this case",
          case.id)
        break
      end
    end

    sent = sent + 1
    local class, detail = run_case(host, port, case, timeout_s, tls)
    tally[class] = (tally[class] or 0) + 1

    local is_notable = (class == "TIMEOUT" or class == "RESET"
      or class == "CORRUPT"
      or (class == "ACCEPT" and case.severity == "high"))
    if is_notable then
      local why = detail
      if class == "ACCEPT" then
        why = "engine accepted a high-severity malformed message"
      elseif class == "TIMEOUT" then
        why = "engine did not respond within timeout"
      end
      notable[#notable + 1] = string.format("[%s] %s - %s",
        class, case.id, why)
      stdnse.debug1("HL7 fuzz: %s -> %s (%s)", case.id, class, detail)
    end
  end

  out["Cases sent"] = string.format("%d / %d", sent, #cases)
  out["Results"] = string.format(
    "ACCEPT=%d ERROR=%d REJECT=%d TIMEOUT=%d RESET=%d CORRUPT=%d",
    tally.ACCEPT, tally.ERROR, tally.REJECT,
    tally.TIMEOUT, tally.RESET, tally.CORRUPT)
  if #notable > 0 then
    out["Notable"] = notable
  else
    out["Note"] = "No hangs, resets or high-severity accepts observed."
  end
  return out
end
