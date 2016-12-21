--
-- Zip Archive dissector
-- Author: Peter Wu <peter@lekensteyn.nl>

--
-- Dissection of Zip file contents
--

local proto_zip = Proto.new("zip_archive", "Zip Archive")

function proto_zip.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "zip"
    --pinfo.cols.info = ""
end

function zip_heur(tvb, pinfo, tree)
    if tvb:raw(0, 2) ~= "PK" then
        return false
    end

    proto_zip.dissector(tvb, pinfo, tree)
    return true
end

-- Register MIME types in case a Zip file appears over HTTP.
DissectorTable.get("media_type"):add("application/zip", proto_zip)
DissectorTable.get("media_type"):add("application/java-archive", proto_zip)

-- Ensure that files can directly be opened (after any FileHandler has accepted
-- it, see below).
proto_zip:register_heuristic("wtap_file", zip_heur)


--
-- File handler (for directly interpreting opening a Zip file in Wireshark)
-- Actually, all it does is recognizing a Zip file and passing one packet to the
-- MIME dissector.
--

local zip_fh = FileHandler.new("Zip", "zip", "Zip archive file reader", "rms")

-- Check if file is really a zip file (return true if it is)
function zip_fh.read_open(file, cinfo)
    -- XXX improve heuristics?
    if file:read(2) ~= "PK" then
        return false
    end

    -- Find end of file and rewind.
    local endpos, err = file:seek("end")
    if not endpos then error("Error while finding end! " .. err) end
    local ok, err = file:seek("set", 0)
    if not ok then error("Non-seekable file! " .. err) end

    cinfo.encap = wtap_encaps.MIME
    cinfo.private_table = {
        endpos = endpos,
    }

    return true
end

-- Read next packet (returns begin offset or false on error)
local function zip_fh_read(file, cinfo, finfo)
    local p = cinfo.private_table
    local curpos = file:seek("cur")

    -- Fal on EOF
    if curpos >= p.endpos then return false end

    finfo.original_length = p.endpos - curpos
    finfo.captured_length = p.endpos - curpos

    if not finfo:read_data(file, finfo.captured_length) then
        -- Partial read?
        print("Hmm, partial read, curpos=" .. curpos .. ", len: " .. finfo.captured_length)
        return false
    end

    return curpos
end
zip_fh.read = zip_fh_read

-- Reads packet at offset (returns true on success and false on failure)
function zip_fh.seek_read(file, cinfo, finfo, offset)
    file:seek("set", offset)
    -- Return a boolean since WS < 2.4 has an undocumented "feature" where
    -- strings (including numbers) are treated as data.
    return zip_fh_read(file, cinfo, finfo) ~= false
end

-- Hints for when to invoke this dissector.
zip_fh.extensions = "zip;jar"

register_filehandler(zip_fh)
