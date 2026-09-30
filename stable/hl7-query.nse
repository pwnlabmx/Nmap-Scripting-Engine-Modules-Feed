local shortport = require "shortport"
local stdnse = require "stdnse"
local nmap = require "nmap"
local hl7 = require "hl7"

description = [[
Queries an HL7 v2.x interface engine for patient demographics over MLLP and
reports any protected health information (PHI) returned without authentication.

Many hospital interface engines and patient-identity services answer HL7
patient queries from any client that can reach the MLLP port. This script
sends a
QRY^A19 (patient query) or QBP^Q22 (find candidates) message for a supplied
patient identifier and parses the response (ADR^A19 / RSP^K22), extracting the
PID segment: patient name, date of birth, sex and address.

This is an intrusive, read-only test: it retrieves patient data. Only run it
against systems you are authorised to assess.
]]

---
-- @usage
-- nmap -p2575 --script hl7-query --script-args hl7-query.patient_id=PAT001 <target>
-- @usage
-- nmap -p2575 --script hl7-query --script-args
--   hl7-query.patient_id=12345,hl7-query.info_model=q22 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2575/tcp open  hl7
-- | hl7-query:
-- |   Query: QRY^A19 for patient id 'PAT001'
-- |   Acknowledgement: AA (Application Accept)
-- |   Records returned: 1
-- |   Patients:
-- |     [Patient] DOE^JOHN^A  DOB=19700101 Sex=M  ID=PAT001
-- |       Address: 123 MAIN ST^^COZUMEL^QR^77600
-- |_  VULNERABILITY: Patient PHI returned without authentication
--
-- @args hl7-query.patient_id  Patient identifier to query. Default: "1"
-- @args hl7-query.info_model  "a19" (QRY^A19) or "q22" (QBP^Q22). Default: a19
-- @args hl7-query.sending_app Sending Application (MSH-3). Default: NMAP
-- @args hl7-query.sending_fac Sending Facility (MSH-4). Default: NMAP
-- @args hl7-query.timeout  Connection/response timeout in seconds. Default: 8
-- @args hl7-query.tls      Set to "true" for MLLP over TLS. Default: false
---

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "intrusive"}

portrule = shortport.port_or_service({2575, 2576}, "hl7", "tcp", "open")

local function arg(name, default)
  return stdnse.get_script_args("hl7-query." .. name) or default
end

--- Extract patient records (PID segments) from a parsed HL7 response.
local function extract_patients(info)
  local patients = {}
  for _, seg in ipairs(info.segments) do
    if seg.id == "PID" then
      patients[#patients + 1] = {
        id      = hl7.field(seg, 3),
        name    = hl7.field(seg, 5),
        dob     = hl7.field(seg, 7),
        sex     = hl7.field(seg, 8),
        address = hl7.field(seg, 11),
      }
    end
  end
  return patients
end

action = function(host, port)
  local out = stdnse.output_table()
  local timeout_s = tonumber(arg("timeout", "8"))
  local tls = arg("tls", "false") == "true"
  local patient_id = arg("patient_id", "1")
  local model = arg("info_model", "a19"):lower()
  local msh_opts = {
    sending_app = arg("sending_app", "NMAP"),
    sending_fac = arg("sending_fac", "NMAP"),
  }

  local msg, label
  if model == "q22" then
    msg = hl7.build_qbp_q22(patient_id, msh_opts)
    label = "QBP^Q22"
  else
    msg = hl7.build_qry_a19(patient_id, msh_opts)
    label = "QRY^A19"
  end

  local ok, resp = hl7.transact(host, port, msg, timeout_s, tls)
  if not ok then
    out["Error"] = "No HL7 response: " .. tostring(resp)
    return out
  end

  local info = hl7.parse_response(resp)
  local patients = extract_patients(info)

  out["Query"] = string.format("%s for patient id '%s'", label, patient_id)
  if info.ack_code ~= "" then
    out["Acknowledgement"] = string.format("%s (%s)",
      info.ack_code, info.ack_text)
  end
  out["Records returned"] = #patients

  if #patients > 0 then
    local lines = {}
    for _, p in ipairs(patients) do
      lines[#lines + 1] = string.format(
        "[Patient] %s  DOB=%s Sex=%s  ID=%s",
        p.name ~= "" and p.name or "(no name)",
        p.dob ~= "" and p.dob or "?",
        p.sex ~= "" and p.sex or "?",
        p.id ~= "" and p.id or "?")
      if p.address ~= "" then
        lines[#lines + 1] = "  Address: " .. p.address
      end
    end
    out["Patients"] = lines
    out["VULNERABILITY"] =
      "Patient PHI returned without authentication"
    nmap.set_port_version(host, port, "hardmatched")
  else
    out["Note"] = "No PID returned (patient not found, or query "
      .. "unsupported/blocked). Try a different patient_id or info_model."
  end
  return out
end
