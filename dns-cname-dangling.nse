local dns = require "dns"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local vulns = require "vulns"

description = [[
Detects dangling CNAME records that may allow subdomain takeover.

A dangling CNAME occurs when a DNS CNAME record points to a target
domain that no longer exists or is unclaimed on a cloud hosting
provider. An attacker who registers the orphaned resource can serve
arbitrary content under the original subdomain, bypassing TLS
certificate validation and same-origin protections.

The script resolves the target hostname, follows any CNAME chain, and
then checks whether the final CNAME target shows signs of being
unclaimed. Detection is performed in two stages:

1. DNS-level check: the CNAME target is resolved. An NXDOMAIN response
   for the target indicates the pointed-to domain does not exist.

2. HTTP-level check (optional): if the CNAME target resolves to a known
   cloud provider, the script performs an HTTP request and inspects the
   response body for provider-specific error fingerprints that indicate
   the resource is unclaimed (e.g., "NoSuchBucket" for AWS S3,
   "There isn't a GitHub Pages site here" for GitHub Pages).

The script supports both hostrule and prerule execution modes. In
hostrule mode, it uses the target hostname from the Nmap scan. In
prerule mode, a domain must be supplied via script arguments.

Results are reported using the Nmap vulns library.
]]

---
-- @usage
-- nmap -sn --script dns-cname-dangling --script-args dns-cname-dangling.domain=old.example.com <dns-server>
--
-- @usage
-- nmap -sn --script dns-cname-dangling \
--   --script-args dns-cname-dangling.domain=cdn.example.com,dns-cname-dangling.http-check=true <dns-server>
--
-- @usage
-- nmap --script dns-cname-dangling --script-args dns-cname-dangling.domain=blog.example.com \
--   --script-args dns-cname-dangling.server=8.8.8.8 -sn <target>
--
-- @usage
-- nmap -p80,443 --script dns-cname-dangling <target-with-hostname>
--
-- @output
-- | dns-cname-dangling:
-- |   VULNERABLE:
-- |   Dangling CNAME record allowing subdomain takeover
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |       A CNAME record points to a destination that appears to be
-- |       unclaimed, potentially allowing an attacker to take control
-- |       of the subdomain by registering the orphaned resource.
-- |
-- |     Extra information:
-- |       domain: cdn.example.com
-- |       CNAME target: cdn.example.com.s3.amazonaws.com
-- |       CNAME target status: NXDOMAIN
-- |       Cloud provider: AWS S3
-- |       HTTP fingerprint matched: NoSuchBucket
-- |
-- |     References:
-- |       https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover
-- |_      https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers
--
-- @args dns-cname-dangling.domain The domain name to check for a
--       dangling CNAME. Required in prerule mode; in hostrule mode
--       the target hostname is used when this argument is absent.
-- @args dns-cname-dangling.server DNS server to query. Optional.
--       Defaults to the target host in hostrule mode or the system
--       resolver in prerule mode.
-- @args dns-cname-dangling.http-check Enable HTTP-level fingerprint
--       detection against known cloud providers (default: true).
-- @args dns-cname-dangling.http-port Port to use for HTTP checks
--       (default: 80).

author = "Paulino Calderon <paulino@calderonpale.com>"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe", "discovery"}

-- Cloud provider CNAME patterns and their HTTP error fingerprints.
-- Each entry contains a Lua pattern to match the CNAME target, a
-- human-readable provider name, and a list of strings to look for
-- in HTTP responses that indicate an unclaimed resource.
local CLOUD_FINGERPRINTS = {
  {
    pattern = "%.s3[%-%.%w]*%.amazonaws%.com$",
    provider = "AWS S3",
    fingerprints = {"NoSuchBucket", "The specified bucket does not exist"},
  },
  {
    pattern = "%.cloudfront%.net$",
    provider = "AWS CloudFront",
    fingerprints = {"Bad request",
        "ERROR: The request could not be satisfied"},
  },
  {
    pattern = "%.elasticbeanstalk%.com$",
    provider = "AWS Elastic Beanstalk",
    fingerprints = {},
  },
  {
    pattern = "%.azurewebsites%.net$",
    provider = "Microsoft Azure",
    fingerprints = {"404 Web Site not found",
        "Azure Web App - Your Azure Function App is up and running"},
  },
  {
    pattern = "%.cloudapp%.azure%.com$",
    provider = "Microsoft Azure",
    fingerprints = {},
  },
  {
    pattern = "%.trafficmanager%.net$",
    provider = "Azure Traffic Manager",
    fingerprints = {},
  },
  {
    pattern = "%.blob%.core%.windows%.net$",
    provider = "Azure Blob Storage",
    fingerprints = {"BlobNotFound", "The specified container does not exist"},
  },
  {
    pattern = "%.github%.io$",
    provider = "GitHub Pages",
    fingerprints = {"There isn't a GitHub Pages site here", "For root URLs"},
  },
  {
    pattern = "%.herokuapp%.com$",
    provider = "Heroku",
    fingerprints = {"No such app", "no%-such%-app",
        "herokucdn.com/error-pages"},
  },
  {
    pattern = "%.netlify%.app$",
    provider = "Netlify",
    fingerprints = {"Not Found - Request ID"},
  },
  {
    pattern = "%.netlify%.com$",
    provider = "Netlify",
    fingerprints = {"Not Found - Request ID"},
  },
  {
    pattern = "%.vercel%.app$",
    provider = "Vercel",
    fingerprints = {},
  },
  {
    pattern = "%.firebaseapp%.com$",
    provider = "Firebase",
    fingerprints = {"Firebase Hosting Setup Complete", "Site Not Found"},
  },
  {
    pattern = "%.web%.app$",
    provider = "Firebase",
    fingerprints = {"Site Not Found"},
  },
  {
    pattern = "%.shopify%.com$",
    provider = "Shopify",
    fingerprints = {"Sorry, this shop is currently unavailable"},
  },
  {
    pattern = "%.myshopify%.com$",
    provider = "Shopify",
    fingerprints = {"Sorry, this shop is currently unavailable"},
  },
  {
    pattern = "%.pantheonsite%.io$",
    provider = "Pantheon",
    fingerprints = {"404 error unknown site"},
  },
  {
    pattern = "%.ghost%.io$",
    provider = "Ghost",
    fingerprints = {},
  },
  {
    pattern = "%.surge%.sh$",
    provider = "Surge.sh",
    fingerprints = {"project not found"},
  },
  {
    pattern = "%.bitbucket%.io$",
    provider = "Bitbucket",
    fingerprints = {"Repository not found"},
  },
  {
    pattern = "%.wordpress%.com$",
    provider = "WordPress.com",
    fingerprints = {"Do you want to register"},
  },
  {
    pattern = "%.fly%.dev$",
    provider = "Fly.io",
    fingerprints = {},
  },
  {
    pattern = "%.unbouncepages%.com$",
    provider = "Unbounce",
    fingerprints = {"The requested URL was not found on this server"},
  },
  {
    pattern = "%.zendesk%.com$",
    provider = "Zendesk",
    fingerprints = {"Help Center Closed"},
  },
}

--- Identify if a CNAME target belongs to a known cloud provider.
--@param cname_target The CNAME target domain string.
--@return provider table or nil
local function identify_provider(cname_target)
  local target_lower = string.lower(cname_target)
  for _, entry in ipairs(CLOUD_FINGERPRINTS) do
    if string.find(target_lower, entry.pattern) then
      return entry
    end
  end
  return nil
end

--- Follow the CNAME chain for a given domain name.
-- Returns the final CNAME target and an indication of whether
-- the target domain resolves (NXDOMAIN or not).
--@param domain The domain name to query.
--@param dns_server Optional DNS server IP to query.
--@return cname_target string or nil, nxdomain boolean, error string or nil
local function resolve_cname(domain, dns_server)
  local opts = {}
  if dns_server then
    opts.host = dns_server
  end
  opts.dtype = "CNAME"
  opts.retAll = true
  opts.retPkt = true

  local status, result = dns.query(domain, opts)
  if not status then
    return nil, false, result
  end

  -- dns.query with retAll returns a table of answers
  -- We want to find the CNAME record
  local cname_target = nil

  if type(result) == "table" then
    -- When retAll is set, result is a list of answer strings
    for _, answer in ipairs(result) do
      if type(answer) == "string" then
        cname_target = answer
      end
    end
  elseif type(result) == "string" then
    cname_target = result
  end

  if not cname_target then
    return nil, false, "No CNAME record found"
  end

  -- Remove trailing dot if present
  cname_target = string.gsub(cname_target, "%.$", "")

  -- Now check if the CNAME target resolves
  local nxdomain = false
  local a_opts = {}
  if dns_server then
    a_opts.host = dns_server
  end
  a_opts.dtype = "A"

  local a_status, a_result = dns.query(cname_target, a_opts)
  if not a_status then
    -- If the query fails, it is likely NXDOMAIN
    nxdomain = true
    stdnse.debug1("CNAME target '%s' returned error: %s", cname_target,
        tostring(a_result))
  end

  return cname_target, nxdomain, nil
end

--- Perform an HTTP request to check for cloud provider error
-- fingerprints indicating an unclaimed resource.
--@param domain The original domain to check (used in Host header).
--@param cname_target The CNAME target domain.
--@param provider The provider table from CLOUD_FINGERPRINTS.
--@param port_number The HTTP port to use.
--@return matched_fingerprint string or nil
local function http_fingerprint_check(domain, cname_target, provider,
    port_number)
  if not provider or not provider.fingerprints
      or #provider.fingerprints == 0 then
    return nil
  end

  -- Try to resolve the original domain to get an IP for the HTTP request
  local ip = nil
  local status, result = dns.query(domain, {dtype = "A"})
  if status and type(result) == "string" then
    ip = result
  elseif status and type(result) == "table" then
    ip = result[1]
  end

  -- Also try the CNAME target
  if not ip then
    status, result = dns.query(cname_target, {dtype = "A"})
    if status and type(result) == "string" then
      ip = result
    elseif status and type(result) == "table" then
      ip = result[1]
    end
  end

  if not ip then
    stdnse.debug1("Cannot resolve IP for HTTP check of '%s'", domain)
    return nil
  end

  -- Perform the HTTP GET with the original domain as Host header
  local http_opts = {
    header = {
      Host = domain,
    },
    bypass_cache = true,
    redirect_ok = false,
  }

  local port_table = {number = port_number, protocol = "tcp"}
  local host_table = {ip = ip}

  local response = http.get(host_table, port_table, "/", http_opts)
  if not response or not response.body then
    stdnse.debug1("HTTP request to %s:%d failed", ip, port_number)
    return nil
  end

  for _, fingerprint in ipairs(provider.fingerprints) do
    if string.find(response.body, fingerprint, 1, true) then
      return fingerprint
    end
  end

  return nil
end

--- Build the vulnerability table and perform detection logic.
--@param domain The domain to check.
--@param dns_server Optional DNS server to use.
--@param do_http Whether to perform HTTP fingerprint checks.
--@param http_port Port number for HTTP checks.
--@return vuln table with populated state and check_results
local function check_dangling_cname(domain, dns_server, do_http, http_port)
  local vuln = {
    title = "Dangling CNAME record allowing subdomain takeover",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    description = [[
A CNAME record points to a destination that appears to be
unclaimed, potentially allowing an attacker to take control
of the subdomain by registering the orphaned resource.
    ]],
    references = {
      'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover',
      'https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers',
    },
  }

  -- Stage 1: Resolve CNAME
  stdnse.debug1("Checking CNAME for domain: %s", domain)
  local cname_target, nxdomain, err = resolve_cname(domain, dns_server)

  if err and not cname_target then
    stdnse.debug1("No CNAME found for '%s': %s", domain, err)
    return vuln
  end

  stdnse.debug1("CNAME target: %s (NXDOMAIN: %s)", cname_target,
      tostring(nxdomain))

  local extra_info = {}
  table.insert(extra_info, string.format("domain: %s", domain))
  table.insert(extra_info, string.format("CNAME target: %s", cname_target))

  -- Identify cloud provider
  local provider = identify_provider(cname_target)
  if provider then
    table.insert(extra_info, string.format("Cloud provider: %s",
        provider.provider))
  end

  if nxdomain then
    table.insert(extra_info, "CNAME target status: NXDOMAIN")
    vuln.state = vulns.STATE.VULN
    stdnse.debug1("CNAME target '%s' returned NXDOMAIN - dangling!",
        cname_target)
  else
    table.insert(extra_info, "CNAME target status: resolves")
  end

  -- Stage 2: HTTP fingerprint check (if enabled and provider known)
  if do_http and provider then
    stdnse.debug1("Performing HTTP fingerprint check against %s",
        provider.provider)
    local matched = http_fingerprint_check(domain, cname_target, provider,
        http_port)
    if matched then
      table.insert(extra_info, string.format("HTTP fingerprint matched: %s",
          matched))
      vuln.state = vulns.STATE.VULN
      stdnse.debug1("HTTP fingerprint matched: %s", matched)
    elseif #provider.fingerprints > 0 then
      table.insert(extra_info, "HTTP fingerprint: no match")
    end
  end

  -- If CNAME target resolves but matches a provider with empty
  -- fingerprints list and we have no HTTP confirmation, mark as
  -- LIKELY_VULN only if there is some other signal
  if vuln.state == vulns.STATE.NOT_VULN and provider and nxdomain then
    vuln.state = vulns.STATE.VULN
  end

  vuln.check_results = extra_info
  return vuln
end

prerule = function()
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain")
  if domain then
    return true
  end
  return false
end

hostrule = function(host)
  -- Run if the host has a hostname we can check
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain")
  if domain then
    return true
  end
  if host.targetname and host.targetname ~= "" then
    return true
  end
  if host.name and host.name ~= "" then
    return true
  end
  return false
end

action = function(host, port)
  local domain = stdnse.get_script_args(SCRIPT_NAME .. ".domain")
  local dns_server = stdnse.get_script_args(SCRIPT_NAME .. ".server")
  local do_http = stdnse.get_script_args(SCRIPT_NAME .. ".http-check")
  local http_port = stdnse.get_script_args(SCRIPT_NAME .. ".http-port")

  -- Parse boolean for http-check (default: true)
  if do_http == nil or do_http == "true" or do_http == "1" then
    do_http = true
  else
    do_http = false
  end

  http_port = tonumber(http_port) or 80

  -- Determine the domain to check
  if not domain then
    if host then
      domain = host.targetname or host.name
    end
  end

  if not domain or domain == "" then
    stdnse.debug1("No domain specified and no hostname available.")
    return nil
  end

  -- Determine DNS server
  if not dns_server and host then
    dns_server = host.ip
  end

  local vuln = check_dangling_cname(domain, dns_server, do_http, http_port)

  -- Only produce output if vulnerability was detected
  if vuln.state == vulns.STATE.NOT_VULN then
    -- Still report via vuln library for consistency and XML output
    local report = vulns.Report:new(SCRIPT_NAME, host)
    return report:make_output(vuln)
  end

  local report = vulns.Report:new(SCRIPT_NAME, host)
  return report:make_output(vuln)
end
