-- Dissector for Realtek 8152 USB Ethernet adapter
-- TODO interrupt dissection? (register accesses, etc.?)

local r8152 = Proto("r8152", "Realtek 8152")

local eth = Dissector.get("eth_withfcs")

local usb_transfer_type = Field.new("usb.transfer_type")
local usb_direction = Field.new("usb.endpoint_number.direction")

r8152.fields.rx = ProtoField.bool("r8152.rx", "Receive Descriptor")
r8152.fields.tx = ProtoField.bool("r8152.tx", "Transmit Descriptor")
r8152.fields.opts = ProtoField.uint32("r8152.opts", "opts", base.HEX)
r8152.fields.rx_len = ProtoField.uint16("r8152.rx_len", "Receive Length", base.DEC, nil, 0x7fff)

function dissect_rx(tvb, pinfo, tree)
    local i
    local offset = 0
    local opts1_tree = tree:add_le(r8152.fields.opts, tvb(offset, 4))
    opts1_tree:add_le(r8152.fields.rx_len, tvb(offset, 4))
    offset = offset + 4
    for i = 2, 6 do
        tree:add_le(r8152.fields.opts, tvb(offset, 4))
        offset = offset + 4
    end
    return offset
end

function dissect_tx(tvb, pinfo, tree)
    local i
    local offset = 0
    for i = 1, 2 do
        tree:add_le(r8152.fields.opts, tvb(offset, 4))
        offset = offset + 4
    end
    return offset
end

function r8152.dissector(tvb, pinfo, tree)
    local offset
    local transfer_type = usb_transfer_type().value
    -- direction: OUT (0), IN (1)
    local is_rx = usb_direction().value == 1

    -- Process only bulk packets
    if transfer_type ~= 3 then
        return 0
    end

    pinfo.cols.protocol = r8152.name

    local dissect_desc

    local r8152_tree = tree:add(r8152, tvb)
    local ti
    if is_rx then
        dissect_desc = dissect_rx
        ti = r8152_tree:add(r8152.fields.rx, tvb(0, 24))
    else
        dissect_desc = dissect_tx
        ti = r8152_tree:add(r8152.fields.tx, tvb(0, 8))
    end
    ti:set_generated(true)
    offset = dissect_desc(tvb, pinfo, r8152_tree)
    r8152_tree:set_len(offset)

    eth(tvb(offset):tvb(), pinfo, tree)
end

function r8152.init()
    local usb_product = DissectorTable.get("usb.product");
    usb_product:add(0x0bda8153, r8152)
end
