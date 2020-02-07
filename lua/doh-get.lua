--
-- Support for DoH GET dissection in Wireshark. Wireshark already supports
-- dissection of the application/dns-message POST request and response bodies,
-- but it does not yet support the GET request parameter. This Lua plugin
-- provides a workaround for that.
-- https://tools.ietf.org/html/rfc8484#section-4.1
--

local doh_get = Proto.new("doh-get", "DNS over HTTPS (GET)")
local media_type = DissectorTable.get("media_type")
local http_path = Field.new("http.request.uri")
local http2_path = Field.new("http2.headers.path")

function doh_get.dissector(tvb, pinfo, tree)
    local path = http2_path() or http_path()
    if not path then
        return
    end

    local dns_b64, sep = string.match(path.value, "[%?&]dns=([A-Za-z0-9_=-]+)(.?)")
    if not dns_b64 then
        return
    end
    -- Check for forbidden values in query string.
    if sep ~= "" and sep ~= "&" then
        return
    end

    local dns_tvb = ByteArray.new(dns_b64, true):base64_decode():tvb("Base64-decoded DNS")

    -- Allow HTTP GET line to be replaced with the DNS one in the Info column.
    pinfo.columns.info:clear_fence()

    -- Call media_type table instead of dns directly, this ensures that the
    -- protocol is properly displayed as "DoH".
    media_type:try("application/dns-message", dns_tvb, pinfo, tree)
end

register_postdissector(doh_get)
