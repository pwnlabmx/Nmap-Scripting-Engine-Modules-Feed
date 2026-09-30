---
-- HL7 v2.x over MLLP library for Nmap NSE scripts.
--
-- Implements the Minimal Lower Layer Protocol (MLLP) framing used to carry
-- HL7 version 2 messages over TCP, plus helpers to build and parse HL7
-- messages (segments, fields, components) and to interpret the acknowledgement
-- (ACK / MSA) returned by an interface engine.
--
-- MLLP frame (HL7 v2, Appendix C): <VT> message <FS><CR>
--   VT = 0x0B (start block), FS = 0x1C (end block), CR = 0x0D (carriage
--   return).  Segments within a message are separated by <CR>.
--
-- Designed to be shared across HL7 NSE scripts (hl7-info, hl7-query,
-- hl7-mllp-fuzzer) so the protocol logic lives in one place.
--
-- OPTIONS:
-- *<code>sending_app</code>  - Sending Application (MSH-3). Default: NMAP
-- *<code>sending_fac</code>  - Sending Facility (MSH-4). Default: NMAP
-- *<code>receiving_app</code>- Receiving Application (MSH-5). Default: empty
-- *<code>receiving_fac</code>- Receiving Facility (MSH-6). Default: empty
--
-- @args hl7.sending_app Sending Application used in MSH-3. Default: NMAP
-- @args hl7.sending_fac Sending Facility used in MSH-4. Default: NMAP
-- @args hl7.receiving_app Receiving Application used in MSH-5. Default: empty
-- @args hl7.receiving_fac Receiving Facility used in MSH-6. Default: empty
--
-- @author Paulino Calderon <paulino@calderonpale.com>
-- @copyright Same as Nmap--See https://nmap.org/book/man-legal.html
---

local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local math = require "math"
local os = os

_ENV = stdnse.module("hl7", stdnse.seeall)

-----------------------------------------------------------------------
-- 1. CONSTANTS
-----------------------------------------------------------------------

--- MLLP control bytes (HL7 v2 Appendix C).
-- @class table
-- @name MLLP
MLLP = {
  VT = "\x0b",   -- Start Block
  FS = "\x1c",   -- End Block
  CR = "\x0d",   -- Carriage Return (segment terminator / frame trailer)
}

--- Default HL7 encoding characters (MSH-2): component, repetition, escape,
-- subcomponent.
-- @class table
-- @name ENCODING
ENCODING = {
  FIELD     = "|",
  COMPONENT = "^",
  REPEAT    = "~",
  ESCAPE    = "\\",
  SUBCOMP   = "&",
}

--- Acknowledgement codes (MSA-1) for the original and enhanced ACK modes.
-- @class table
-- @name ACK_CODE
ACK_CODE = {
  AA = "Application Accept",
  AE = "Application Error",
  AR = "Application Reject",
  CA = "Commit Accept",
  CE = "Commit Error",
  CR = "Commit Reject",
}

--- Common HL7 v2 default TCP ports for MLLP.
-- @class table
-- @name PORTS
PORTS = { 2575, 2576 }

--- Default maximum message size accepted when reading a frame (bytes).
MAX_MSG_SIZE = 5 * 1024 * 1024

-----------------------------------------------------------------------
-- 2. LOW-LEVEL UTILITIES
-----------------------------------------------------------------------

--- Split a string on a single-character separator (literal, not a pattern).
-- @param s   String to split
-- @param sep Single-character separator
-- @return List of substrings (at least one element)
function split(s, sep)
  local parts = {}
  local start = 1
  while true do
    local idx = string.find(s, sep, start, true)
    if not idx then
      parts[#parts + 1] = string.sub(s, start)
      break
    end
    parts[#parts + 1] = string.sub(s, start, idx - 1)
    start = idx + 1
  end
  return parts
end

--- Strip a trailing CR and/or LF from a string.
function chomp(s)
  return (string.gsub(s, "[\r\n]+$", ""))
end

--- Generate a message control ID (MSH-10) unique enough for one scan.
function control_id()
  return string.format("NMAP%d%d", os.time(), math.random(1000, 9999))
end

--- Current timestamp in HL7 format (MSH-7): YYYYMMDDHHMMSS.
function timestamp()
  return os.date("!%Y%m%d%H%M%S")
end

-----------------------------------------------------------------------
-- 3. MLLP FRAMING
-----------------------------------------------------------------------

--- Wrap an HL7 message in an MLLP frame.
-- @param msg Raw HL7 message (segments separated by CR)
-- @return Framed bytes: VT .. msg .. FS .. CR
function mllp_wrap(msg)
  return MLLP.VT .. msg .. MLLP.FS .. MLLP.CR
end

--- Remove the MLLP framing from received bytes, if present.
-- @param data Received bytes
-- @return The message body with VT/FS/CR framing removed
function mllp_unwrap(data)
  local body = data
  body = string.gsub(body, "^" .. MLLP.VT, "")
  body = string.gsub(body, MLLP.FS .. MLLP.CR .. "?$", "")
  return body
end

-----------------------------------------------------------------------
-- 4. NETWORK LAYER
-----------------------------------------------------------------------

--- Create a new Nmap socket with a timeout in seconds.
function new_sock(timeout_s)
  local s = nmap.new_socket()
  s:set_timeout((timeout_s or 10) * 1000)
  return s
end

--- Connect a socket.  Returns ok, err.
-- @param sock Nmap socket
-- @param host Host object
-- @param port Port object (or number)
-- @param tls  If true, negotiate TLS (MLLP-over-TLS); otherwise plain TCP
function connect(sock, host, port, tls)
  return sock:connect(host, port, tls and "ssl" or "tcp")
end

--- Fetch the peer's TLS certificate from a connected TLS socket, if any.
-- @param sock Connected Nmap socket (TLS)
-- @return certificate table (see nmap sslcert), or nil
function get_cert(sock)
  local ok, cert = pcall(function() return sock:get_ssl_certificate() end)
  if ok then return cert end
  return nil
end

--- Send an HL7 message wrapped in an MLLP frame.
-- @param sock Nmap socket
-- @param msg  Raw HL7 message
-- @return ok (bool), err (string or nil)
function send_message(sock, msg)
  return sock:send(mllp_wrap(msg))
end

--- Receive one complete MLLP frame and return the unwrapped HL7 message.
-- Reads until the FS (end block) byte is seen or the socket errors/timeouts.
-- @param sock      Nmap socket
-- @param max_size  Maximum bytes to accumulate (default: MAX_MSG_SIZE)
-- @return ok (bool), message_or_err (string), raw (string – full framed bytes)
function recv_message(sock, max_size)
  max_size = max_size or MAX_MSG_SIZE
  local buf = ""
  while true do
    local fs = string.find(buf, MLLP.FS, 1, true)
    if fs then
      local raw = buf
      return true, mllp_unwrap(string.sub(buf, 1, fs + 1)), raw
    end
    if #buf >= max_size then
      return false, "MESSAGE_TOO_LARGE", buf
    end
    local ok, chunk = sock:receive()
    if not ok then
      if chunk and string.find(chunk, "TIMEOUT") then
        return false, "TIMEOUT", buf
      end
      -- Some engines close the connection after replying without a clean FS.
      if #buf > 0 then
        return true, mllp_unwrap(buf), buf
      end
      return false, "CONNECTION_RESET", buf
    end
    buf = buf .. chunk
  end
end

-----------------------------------------------------------------------
-- 5. MESSAGE BUILDING
-----------------------------------------------------------------------

--- Build an MSH segment.
-- MSH-1 is the field separator itself and MSH-2 the encoding characters, so
-- they are emitted literally; the remaining fields follow.
-- @param t Table with optional keys: sending_app, sending_fac, receiving_app,
--          receiving_fac, message_type (MSH-9, e.g. "QRY^A19"),
--          control_id (MSH-10), processing_id (MSH-11, default "P"),
--          version (MSH-12, default "2.5")
-- @return MSH segment string
function build_msh(t)
  t = t or {}
  local enc = ENCODING.COMPONENT .. ENCODING.REPEAT
            .. ENCODING.ESCAPE .. ENCODING.SUBCOMP
  local fields = {
    "MSH",
    enc,
    t.sending_app   or "NMAP",
    t.sending_fac   or "NMAP",
    t.receiving_app or "",
    t.receiving_fac or "",
    t.timestamp     or timestamp(),
    "",
    t.message_type  or "QRY^A19",
    t.control_id    or control_id(),
    t.processing_id or "P",
    t.version       or "2.5",
  }
  -- MSH-1 (the separator) is implicit between "MSH" and the encoding chars.
  return "MSH" .. ENCODING.FIELD .. table.concat(fields, ENCODING.FIELD, 2)
end

--- Join a list of segment strings into an HL7 message (CR-separated).
function build_message(segments)
  return table.concat(segments, MLLP.CR)
end

--- Build a QRY^A19 (patient query) message for a patient identifier.
-- @param patient_id Patient identifier to query (QRD-8)
-- @param msh_opts   Optional table passed through to build_msh
-- @return Raw HL7 message string
function build_qry_a19(patient_id, msh_opts)
  msh_opts = msh_opts or {}
  msh_opts.message_type = "QRY^A19"
  local cid = msh_opts.control_id or control_id()
  msh_opts.control_id = cid
  local msh = build_msh(msh_opts)
  -- QRD: query definition. Fields are positional; only the ones a server
  -- needs to identify a patient query are populated.
  local qrd = table.concat({
    "QRD",
    timestamp(),      -- QRD-1 query date/time
    "R",              -- QRD-2 query format code (R = record-oriented)
    "I",              -- QRD-3 query priority (I = immediate)
    cid,              -- QRD-4 query ID
    "", "",           -- QRD-5, QRD-6
    "1^RD",           -- QRD-7 quantity limited request
    patient_id or "", -- QRD-8 who subject filter (patient ID)
    "DEM",            -- QRD-9 what subject filter (DEM = demographics)
  }, ENCODING.FIELD)
  return build_message({ msh, qrd })
end

--- Build a QBP^Q22 (find candidates) message for a patient identifier.
-- @param patient_id Patient identifier to query
-- @param msh_opts   Optional table passed through to build_msh
-- @return Raw HL7 message string
function build_qbp_q22(patient_id, msh_opts)
  msh_opts = msh_opts or {}
  msh_opts.message_type = "QBP^Q22^QBP_Q21"
  local cid = msh_opts.control_id or control_id()
  msh_opts.control_id = cid
  local msh = build_msh(msh_opts)
  local qpd = table.concat({
    "QPD",
    "Q22^Find Candidates^HL7",  -- QPD-1 message query name
    cid,                        -- QPD-2 query tag
    "@PID.3.1^" .. (patient_id or ""),  -- QPD-3 demographic fields
  }, ENCODING.FIELD)
  local rcp = table.concat({ "RCP", "I", "10^RD" }, ENCODING.FIELD)
  return build_message({ msh, qpd, rcp })
end

--- Build a PID (patient identification) segment.
-- @param t Table with optional keys: id, name (PID-5, e.g. "DOE^JOHN"),
--          dob (PID-7), sex (PID-8)
-- @return PID segment string
function build_pid(t)
  t = t or {}
  return table.concat({
    "PID",
    "1",                    -- PID-1 set id
    "",                     -- PID-2
    t.id   or "",           -- PID-3 patient identifier list
    "",                     -- PID-4
    t.name or "ZZZTEST^NMAP",  -- PID-5 patient name (synthetic by default)
    "",                     -- PID-6
    t.dob  or "",           -- PID-7 date of birth
    t.sex  or "",           -- PID-8 sex
  }, ENCODING.FIELD)
end

--- Build an ORM^O01 (general order) message: MSH + PID + ORC + OBR.
-- Used to test whether an engine accepts an unauthenticated new order.
-- @param t Table: patient_id, patient_name, order_control (ORC-1, default
--          "NW" new order), placer (order number), service (OBR-4 universal
--          service id, e.g. "CBC^Complete Blood Count"), plus MSH keys
-- @return Raw HL7 message string
function build_orm_o01(t)
  t = t or {}
  local msh_opts = {
    sending_app   = t.sending_app,
    sending_fac   = t.sending_fac,
    processing_id = t.processing_id or "T",
    message_type  = "ORM^O01",
    control_id    = t.control_id,
  }
  local placer = t.placer or ("NMAP" .. control_id())
  local service = t.service or "CBC^COMPLETE BLOOD COUNT^L"
  local orc = table.concat({
    "ORC",
    t.order_control or "NW",  -- ORC-1 order control (NW = new order)
    placer,                   -- ORC-2 placer order number
    "",                       -- ORC-3 filler order number
  }, ENCODING.FIELD)
  local obr = table.concat({
    "OBR",
    "1",                      -- OBR-1 set id
    placer,                   -- OBR-2 placer order number
    "",                       -- OBR-3 filler order number
    service,                  -- OBR-4 universal service identifier
  }, ENCODING.FIELD)
  return build_message({
    build_msh(msh_opts),
    build_pid({ id = t.patient_id, name = t.patient_name }),
    orc, obr,
  })
end

--- Build an ORU^R01 (observation result) message: MSH + PID + OBR + OBX.
-- Used to test whether an engine accepts an unauthenticated (potentially
-- forged) result. Default value is an obviously synthetic test result.
-- @param t Table: patient_id, patient_name, service (OBR-4), obs_id (OBX-3,
--          e.g. "GLU^Glucose"), value (OBX-5), value_type (OBX-2, default
--          "NM"), units (OBX-6), plus MSH keys
-- @return Raw HL7 message string
function build_oru_r01(t)
  t = t or {}
  local msh_opts = {
    sending_app   = t.sending_app,
    sending_fac   = t.sending_fac,
    processing_id = t.processing_id or "T",
    message_type  = "ORU^R01",
    control_id    = t.control_id,
  }
  local service = t.service or "GLU^GLUCOSE^L"
  local obr = table.concat({
    "OBR",
    "1",                          -- OBR-1 set id
    t.placer or "",               -- OBR-2 placer order number
    "",                           -- OBR-3 filler order number
    service,                      -- OBR-4 universal service identifier
  }, ENCODING.FIELD)
  local obx = table.concat({
    "OBX",
    "1",                          -- OBX-1 set id
    t.value_type or "NM",         -- OBX-2 value type (NM = numeric)
    t.obs_id or "GLU^GLUCOSE^L",  -- OBX-3 observation identifier
    "",                           -- OBX-4 observation sub-id
    t.value or "9999",            -- OBX-5 observation value (synthetic)
    t.units or "mg/dL",           -- OBX-6 units
    "",                           -- OBX-7 references range
    t.abnormal or "HH",           -- OBX-8 abnormal flags
    "",                           -- OBX-9
    "",                           -- OBX-10
    "F",                          -- OBX-11 observation result status (final)
  }, ENCODING.FIELD)
  return build_message({
    build_msh(msh_opts),
    build_pid({ id = t.patient_id, name = t.patient_name }),
    obr, obx,
  })
end

--- Build an EVN (event type) segment.
function build_evn(event_code)
  return table.concat({ "EVN", event_code or "", timestamp() },
    ENCODING.FIELD)
end

--- Build a minimal PV1 (patient visit) segment.
-- @param t Table with optional keys: patient_class (PV1-2, default "I"),
--          location (PV1-3)
function build_pv1(t)
  t = t or {}
  return table.concat({
    "PV1",
    "1",                        -- PV1-1 set id
    t.patient_class or "I",     -- PV1-2 patient class (I = inpatient)
    t.location or "",           -- PV1-3 assigned patient location
  }, ENCODING.FIELD)
end

--- Build an ADT message (patient admission/update/merge feed).
-- Used to test whether an engine accepts unauthenticated ADT messages, which
-- can create, alter or merge patient records (patient misidentification and
-- wrong-patient risk).
-- @param event Trigger event: "A01" (admit), "A08" (update patient info),
--              "A40" (merge patient - patient identifier list)
-- @param t Table: patient_id, patient_name, prior_id (A40 merge source,
--          MRG-1), patient_class, plus MSH keys
-- @return Raw HL7 message string
function build_adt(event, t)
  t = t or {}
  event = event or "A01"
  local msh_opts = {
    sending_app   = t.sending_app,
    sending_fac   = t.sending_fac,
    processing_id = t.processing_id or "T",
    message_type  = "ADT^" .. event,
    control_id    = t.control_id,
  }
  local segs = {
    build_msh(msh_opts),
    build_evn(event),
    build_pid({ id = t.patient_id, name = t.patient_name }),
  }
  if event == "A40" then
    -- MRG-1 = prior patient identifier list (the record merged away).
    segs[#segs + 1] = table.concat({
      "MRG", t.prior_id or "ZZZOLD" }, ENCODING.FIELD)
  else
    segs[#segs + 1] = build_pv1({ patient_class = t.patient_class })
  end
  return build_message(segs)
end

-----------------------------------------------------------------------
-- 6. MESSAGE PARSING
-----------------------------------------------------------------------

--- Parse a raw HL7 message into a list of segments.
-- Each returned segment has its id in the `id` key and its raw fields in the
-- `fields` list.  Use field(seg, n) to read HL7 field n rather than indexing
-- `fields` directly, since MSH and ordinary segments are laid out differently
-- (MSH-1 is the field separator).
-- @param raw Raw HL7 message (framing already removed)
-- @return List of { id = "MSH", fields = {..} } tables
function parse_message(raw)
  local segments = {}
  raw = string.gsub(raw, MLLP.VT, "")
  raw = string.gsub(raw, MLLP.FS, "")
  -- Segments may be separated by CR, LF or CRLF depending on the sender.
  for _, line in ipairs(split_lines(raw)) do
    if #line >= 3 then
      local id = string.sub(line, 1, 3)
      local fields
      if id == "MSH" then
        -- MSH-1 is the field separator itself; index it so field(seg, n)
        -- returns MSH-n (MSH-1 = "|", MSH-2 = encoding chars, ...).
        local rest = split(string.sub(line, 5), ENCODING.FIELD)
        fields = { ENCODING.FIELD }
        for _, f in ipairs(rest) do
          fields[#fields + 1] = f
        end
      else
        fields = split(line, ENCODING.FIELD)
      end
      segments[#segments + 1] = { id = id, fields = fields }
    end
  end
  return segments
end

--- Split a raw message into segment lines on CR, LF or CRLF.
function split_lines(raw)
  local lines = {}
  for line in string.gmatch(raw, "[^\r\n]+") do
    lines[#lines + 1] = line
  end
  return lines
end

--- Return the first segment with the given id, or nil.
-- @param segments Output of parse_message
-- @param id       Segment id, e.g. "MSA"
function find_segment(segments, id)
  for _, seg in ipairs(segments) do
    if seg.id == id then return seg end
  end
  return nil
end

--- Get field N of a segment (1-based HL7 field numbering).
-- For MSH, field N maps directly to index N (MSH-2 = encoding chars); for all
-- other segments field N is the Nth field after the segment id.
-- @param seg Segment table from parse_message
-- @param n   HL7 field number
-- @return Field string, or "" if absent
function field(seg, n)
  if not seg then return "" end
  if seg.id == "MSH" then
    return seg.fields[n] or ""
  end
  return seg.fields[n + 1] or ""
end

--- Get component C (1-based) of a field value (split on the component sep).
function component(value, c)
  if not value or value == "" then return "" end
  local comps = split(value, ENCODING.COMPONENT)
  return comps[c] or ""
end

-----------------------------------------------------------------------
-- 7. ACK / RESPONSE INTERPRETATION
-----------------------------------------------------------------------

--- Interpret an HL7 response, extracting acknowledgement details.
-- @param raw Raw HL7 response message (framing removed)
-- @return Table with: ack_code (MSA-1), ack_text (human readable),
--         control_id (MSA-2), text_message (MSA-3), sending_app (MSH-3),
--         sending_fac (MSH-4), version (MSH-12), message_type (MSH-9),
--         segments (parsed list)
function parse_response(raw)
  local segments = parse_message(raw)
  local msh = find_segment(segments, "MSH")
  local msa = find_segment(segments, "MSA")
  local result = {
    segments     = segments,
    ack_code     = "",
    ack_text     = "",
    control_id   = "",
    text_message = "",
    sending_app  = "",
    sending_fac  = "",
    version      = "",
    message_type = "",
  }
  if msh then
    result.sending_app  = component(field(msh, 3), 1)
    result.sending_fac  = component(field(msh, 4), 1)
    result.message_type = field(msh, 9)
    result.version      = field(msh, 12)
  end
  if msa then
    result.ack_code     = field(msa, 1)
    result.control_id   = field(msa, 2)
    result.text_message = field(msa, 3)
    result.ack_text     = ACK_CODE[result.ack_code] or "Unknown"
  end
  return result
end

-----------------------------------------------------------------------
-- 8. HIGH-LEVEL TRANSACTION
-----------------------------------------------------------------------

--- Open a connection, send one HL7 message and read one response.
-- @param host      Nmap host object
-- @param port      Nmap port object (or number)
-- @param msg       Raw HL7 message to send
-- @param timeout_s Socket timeout in seconds
-- @param tls       If true, use MLLP-over-TLS instead of plain TCP
-- @return ok (bool), response_or_err (string), raw_framed (string)
function transact(host, port, msg, timeout_s, tls)
  local sock = new_sock(timeout_s)
  local ok, err = connect(sock, host, port, tls)
  if not ok then
    sock:close()
    return false, "CONNECT_FAILED: " .. tostring(err), nil
  end
  ok, err = send_message(sock, msg)
  if not ok then
    sock:close()
    return false, "SEND_FAILED: " .. tostring(err), nil
  end
  local rok, resp, raw = recv_message(sock)
  sock:close()
  if not rok then
    return false, resp, raw
  end
  return true, resp, raw
end

return _ENV
