--
-- Wireshark listener to identify unusual TLS Alerts and associated domains.
-- Author: Peter Wu <peter@lekensteyn.nl>
--
-- Load in Wireshark, then open the Tools -> TLS Alerts menu, or use tshark:
--
--  $ tshark -q -Xlua_script:tls-alerts.lua -r some.pcapng
--  shavar.services.mozilla.com             1x Bad Certificate (42)
--  aus5.mozilla.org                        3x Bad Certificate (42), 1x Unknown CA (48)
--

--local quic_stream = Field.new("quic.stream")
local tls_sni = Field.new("tls.handshake.extensions_server_name")
local tls_alert = Field.new("tls.alert_message.desc")

-- Map from TCP stream -> SNI
local snis
-- Map from SNI -> (map of alerts -> counts)
local alerts

local tw
local function reset_stats()
    snis = {}
    alerts = {}
    if gui_enabled() then
        tw:clear()
    end
end

local function tap_packet(pinfo, tvb, tcp_info)
    local tcp_stream = tcp_info.th_stream
    if not tcp_stream then
        print('TCP stream somehow not found, is this QUIC? pkt=' .. pinfo.number)
        return
    end

    local f_sni = tls_sni()
    if f_sni then
        snis[tcp_stream] = f_sni.value
    end
    -- Ignore "Close Notify (0)" alerts since these are not unusual.
    local f_alert = tls_alert()
    if f_alert and f_alert.value ~= 0 then
        local sni = snis[tcp_stream] or string.format("<unknown SNI on tcp.stream==%d>", tcp_stream)
        -- Store counters for SNI -> Alerts mappings
        local sni_alerts = alerts[sni]
        if not alerts[sni] then
            sni_alerts = {}
            alerts[sni] = sni_alerts
        end
        local count = sni_alerts[f_alert.display]
        if not count then
            sni_alerts[f_alert.display] = 1
        else
            sni_alerts[f_alert.display] = count + 1
        end
    end
end

local function round_to_multiple_of(val, multiple)
    local rest = val % multiple
    if rest == 0 then
        return val
    else
        return val - rest + multiple
    end
end

local function output_all(callback, need_newline)
    -- Align the domain to a multiple of four columns
    local max_length = 16
    for sni in pairs(alerts) do
        if #sni > max_length then
            max_length = round_to_multiple_of(#sni + 1, 4) - 1
        end
    end
    local fmt = "%-" .. max_length .. "s %s"
    if need_newline then fmt = fmt .. "\n" end

    for sni, alert_counts in pairs(alerts) do
        table.sort(alert_counts, function(a, b) return a > b end)
        local all_alerts
        for alert, count in pairs(alert_counts) do
            local sep = ""
            local chunk = string.format("%dx %s", count, alert)
            if all_alerts then
                all_alerts = all_alerts .. ", " .. chunk
            else
                all_alerts = chunk
            end
        end
        callback(string.format(fmt, sni, all_alerts))
    end
end

-- Called periodically in the Wireshark GUI
local function gui_draw()
    tw:clear()
    output_all(function(text)
        tw:append(text .. "\n")
    end)
end

-- Called at the end of tshark
local function cli_draw()
    output_all(print)
end

local function activate_tap()
    -- Match TLS Client Hello with SNI extension or TLS alerts.
    local tap = Listener.new("tcp", "(tls.handshake.type==1 and tls.handshake.extensions_server_name) or tls.alert_message")

    if gui_enabled() then
        tw = TextWindow.new("TLS Alerts")
        tw:set_atclose(function()
            tap:remove()
            tw = nil
        end)
        tap.draw = gui_draw
    else
        tap.draw = cli_draw
    end

    tap.packet = tap_packet
    tap.reset = reset_stats
    reset_stats()
    if gui_enabled() then
        retap_packets()
    end
end

if gui_enabled() then
    register_menu("TLS Alerts", activate_tap, MENU_TOOLS_UNSORTED)
else
    activate_tap()
end
