-- Dissector for Graylog Extended Log Format (GELF)
-- Docs: http://docs.graylog.org/en/2.0/pages/gelf.html

local gelf = Proto("GELF", "Graylog Extended Log Format")

local json = Dissector.get("json")

gelf.fields.data = ProtoField.string("gelf.data", "Message")

function gelf.dissector(tvb, pinfo, tree)
    if tvb:raw(0, 2) ~= "\x1f\x8b" then
        -- not a gzip header, ignore
        return 0
    end

    pinfo.cols.protocol = "GELF"

    local tvb_uncompress = tvb():uncompress("GELF")

    -- raw text
    tree:add(gelf.fields.data, tvb_uncompress)

    -- as JSON structure
    json:call(tvb_uncompress:tvb(), pinfo, tree)
end

gelf:register_heuristic("udp", gelf.dissector)
