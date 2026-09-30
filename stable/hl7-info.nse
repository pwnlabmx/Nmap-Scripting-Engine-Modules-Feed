local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local hl7 = require "hl7"

description = [[
Detects HL7 v2.x interface engines speaking the Minimal Lower Layer Protocol
(MLLP) and fingerprints the responder.

Hospitals move ADT (admit/discharge/transfer), orders and results between the
EHR, laboratory, radiology and other systems as HL7 v2 messages carried over
MLLP (usually TCP 2575). MLLP has no authentication or encryption of its own,
so an exposed interface engine typically accepts messages from anyone who can
reach the port.

The script opens an MLLP connection, sends a minimal read-only patient query
with no patient identifier, and reads the acknowledgement. From the reply it
reports the responding application and facility (MSH-3/MSH-4), the HL7 version
(MSH-12) and the acknowledgement code (MSA-1). Receiving any acknowledgement
means the engine processed an unauthenticated message.

No patient data is requested. Use dicom-style follow-up script hl7-query to
demonstrate patient-data exposure.
]]

---
-- @usage nmap -p2575 --script hl7-info <target>
-- @usage nmap -sV --script hl7-info <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-info:
-- |   HL7 MLLP interface engine discovered!
-- |   Responding application: LABENGINE
-- |   Responding facility: LABHOSP
-- |   HL7 version: 2.5
-- |   Acknowledgement: AA (Application Accept)
-- |   config: Accepts unauthenticated HL7 messages (Insecure)
-- |_  security: No TLS (plaintext HL7 - PHI transmitted in the clear)
--
-- @args hl7-info.sending_app  Sending Application (MSH-3). Default: NMAP
-- @args hl7-info.sending_fac  Sending Facility (MSH-4). Default: NMAP
-- @args hl7-info.timeout  Connection/response timeout in seconds. Default: 8
-- @args hl7-info.tls      Force transport: "true" (MLLP over TLS), "false"
--                         (plaintext), or unset to auto-detect.
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "default", "safe"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-info." .. name) or default
end

--- Probe the port with a read-only query over plain TCP or TLS.
-- @return ok (bool), parsed_info (table), cert (table or nil)
local function probe(host, port, timeout_s, tls)
  local sock = hl7.new_sock(timeout_s)
  local ok = hl7.connect(sock, host, port, tls)
  if not ok then
    sock:close()
    return false
  end
  -- Minimal read-only query with no patient identifier: elicits an ACK
  -- without requesting any patient data.
  local msg = hl7.build_qry_a19("", {
    sending_app = arg("sending_app", "NMAP"),
    sending_fac = arg("sending_fac", "NMAP"),
    processing_id = "T",
  })
  ok = hl7.send_message(sock, msg)
  if not ok then
    sock:close()
    return false
  end
  local rok, resp = hl7.recv_message(sock)
  local cert = tls and hl7.get_cert(sock) or nil
  sock:close()
  if not rok then
    return false
  end
  return true, hl7.parse_response(resp), cert
end

--- Format a certificate date, which may be a string or a date table.
local function fmt_date(d)
  if type(d) == "table" then
    if d.year then
      return string.format("%04d-%02d-%02d %02d:%02d:%02d",
        d.year or 0, d.month or 0, d.day or 0,
        d.hour or 0, d.min or 0, d.sec or 0)
    end
    return "?"
  end
  return tostring(d)
end

--- Describe a TLS certificate as a list of output lines.
local function cert_lines(cert)
  local subj = cert.subject and cert.subject.commonName or "?"
  local iss  = cert.issuer and cert.issuer.commonName or "?"
  local exp  = "?"
  if cert.validity and cert.validity.notAfter then
    exp = fmt_date(cert.validity.notAfter)
  end
  local lines = {
    "Subject CN: " .. subj,
    "Issuer CN: " .. iss,
    "Not after: " .. exp,
  }
  if subj ~= "?" and subj == iss then
    lines[#lines + 1] = "Self-signed certificate"
  end
  return lines
end

action = function(host, port)
  local out = stdnse.output_table()
  local timeout_s = tonumber(arg("timeout", "8"))

  -- Transport selection: tls=true forces TLS, tls=false forces plaintext,
  -- unset auto-detects (plaintext first, then MLLP-over-TLS).
  local tls_arg = arg("tls", nil)
  local attempts
  if tls_arg == "true" then
    attempts = { true }
  elseif tls_arg == "false" then
    attempts = { false }
  else
    attempts = { false, true }
  end

  local ok, info, cert, used_tls
  for _, t in ipairs(attempts) do
    local o, i, c = probe(host, port, timeout_s, t)
    if o then
      ok, info, cert, used_tls = o, i, c, t
      break
    end
  end
  if not ok then
    stdnse.debug1("HL7: no MLLP response (plaintext or TLS)")
    return nil
  end

  port.version.name = used_tls and "hl7s" or "hl7"
  port.version.product = "HL7 MLLP interface engine"
  if info.version ~= "" then
    port.version.version = info.version
  end
  nmap.set_port_version(host, port, "hardmatched")

  out["hl7"] = "HL7 MLLP interface engine discovered!"
  if info.sending_app ~= "" then
    out["Responding application"] = info.sending_app
  end
  if info.sending_fac ~= "" then
    out["Responding facility"] = info.sending_fac
  end
  if info.version ~= "" then
    out["HL7 version"] = info.version
  end
  if info.ack_code ~= "" then
    out["Acknowledgement"] = string.format("%s (%s)",
      info.ack_code, info.ack_text)
  end
  out["config"] = "Accepts unauthenticated HL7 messages (Insecure)"

  if used_tls then
    out["Transport"] = "MLLP over TLS (encrypted)"
    if cert then
      out["TLS certificate"] = cert_lines(cert)
    end
    out["security"] = "TLS in use, but no HL7-level authentication - any "
      .. "TLS client can send messages"
  else
    out["Transport"] = "Plaintext MLLP (no TLS)"
    out["security"] =
      "No TLS (plaintext HL7 - PHI transmitted in the clear)"
  end
  return out
end
