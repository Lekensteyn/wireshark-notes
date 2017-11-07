-- trivial protocol example
-- declare our protocol
trivial_proto = Proto("trivial", "Trivial Protocol")

function dissect_foo(tvb, pinfo, tree)
    nothing();
    local subtree = tree:add(trivial_proto, tvb(),"Trivial Protocol Data")
    subtree:add(tvb(3,2), "Len: " .. tvb(3,2):uint())
end

function get_pdu_len(tvb, pinfo, tree)
    return tvb(3, 2):uint()
end

function trivial_proto.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "TRIVIAL"
    dissect_tcp_pdus(tvb, tree, 5, get_pdu_len, dissect_foo)
end


tcp_table = DissectorTable.get("tcp.port")
tcp_table:add(7777, trivial_proto)
tcp_table:add(443, trivial_proto)
