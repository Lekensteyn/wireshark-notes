-- trivial protocol example
-- declare our protocol
local trivial_proto = Proto("trivial", "Trivial Protocol")

-- Will be called below in trivial_proto.dissector
local function dissect_foo(tvb, pinfo, tree)
    -- Add an additional "layer" (think of IP, TCP, etc.)
    local subtree = tree:add(trivial_proto, tvb(), "Trivial Protocol Data")

    -- To that layer, add a field that highlights the last two bytes of the
    -- buffer ("tvb") and add the textual label "Len: " followed by the length
    -- extracted from the tvb.
    subtree:add(tvb(3,2), "Len: " .. tvb(3,2):uint())
end

-- Will be used in trivial_proto.dissector
local function get_pdu_len(tvb, pinfo, tree)
    -- Extract 2 bytes from offset 3 (so the last two bytes of a five-byte
    -- buffer). This will be the length of the full PDU.
    return tvb(3, 2):uint()
end

function trivial_proto.dissector(tvb, pinfo, tree)
    -- Change the "Protocol" column
    pinfo.cols.protocol = "TRIVIAL"

    -- Try to call the "dissect_foo" dissector for each PDU ("message"). The
    -- PDU is expected to have a header of five bytes and the actual length is
    -- returned by "get_pdu_len".
    dissect_tcp_pdus(tvb, tree, 5, get_pdu_len, dissect_foo)
end

-- Ensure that the dissector is called for TCP port numbers 7777 and 443.
local tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(7777, trivial_proto)
tcp_table:add(443, trivial_proto)

-- For another example, see
-- https://www.wireshark.org/docs/wsdg_html_chunked/wslua_dissector_example.html
