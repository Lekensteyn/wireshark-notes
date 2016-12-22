--
-- Zip Archive dissector
-- Author: Peter Wu <peter@lekensteyn.nl>
--
-- Information about the file format:
-- https://en.wikipedia.org/wiki/Zip_(file_format)#File_headers
-- https://web.archive.org/https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
-- (.ZIP File Format Specification 6.3.4, Revised October 1, 2014)
--

--
-- Dissection of Zip file contents
--

-- takes a table where keys are the field names and values are descriptions of
-- fields. If a value is a table without numeric indicdes, assume that it is a
-- nested tree.
local function make_fields(field_abbr_prefix, field_defs, hfs_out, hfs_list_out)
    for name, params in pairs(field_defs) do
        if #params == 0 then
            -- Assume nested table, flatten it
            hfs_out[name] = {}
            make_fields(field_abbr_prefix .. name .. ".", params,
                hfs_out[name], hfs_list_out)
        else
            local proto_field_constructor = params[1]
            local field_abbr = string.gsub(field_abbr_prefix .. name, "%._$", "")
            local field
            if type(params[2]) == "string" then
                -- Name was given, use it
                field = proto_field_constructor(field_abbr, unpack(params, 2))
            else
                -- Name was not given, use field name (the suffix)
                field = proto_field_constructor(field_abbr, name, unpack(params, 2))
            end
            hfs_out[name] = field
            table.insert(hfs_list_out, field)
        end
    end
end

local proto_zip = Proto.new("zip_archive", "Zip Archive")
proto_zip.prefs.decompress = Pref.bool("Decompress file data", true,
    "Whether file data should be decompressed or not.")
local hf = {}
local general_purpose_flags_def = {
    _ = {ProtoField.uint16, "General purpose bit flag", base.HEX},
    -- TODO fix wslua documentation, it is wrong on ProtoField.bool.
    encrypted       = {ProtoField.bool, "Is encrypted",             16, nil, 0x0001},
    comp_option     = {ProtoField.bool, "Compr-specific options",   16, nil, 0x0006},
    has_data_desc   = {ProtoField.bool, "Data descriptor present",  16, nil, 0x0008},
    enhanced_deflate= {ProtoField.bool, "Enhanced deflating",       16, nil, 0x0010},
    compr_patched   = {ProtoField.bool, "Compressed patched data",  16, nil, 0x0020},
    strong_encrypt  = {ProtoField.bool, "Strong encryption",        16, nil, 0x0040},
    unused          = {ProtoField.bool, "Unused",                   16, nil, 0x0780},
    lang_encoding   = {ProtoField.bool, "Language encoding",        16, {"UTF-8", "System-specific"}, 0x0800},
    enhanced_compr  = {ProtoField.bool, "Enhanced compression",     16, nil, 0x1000},
    hdr_data_masked = {ProtoField.bool, "Local Header data masked", 16, nil, 0x2000},
    reserved        = {ProtoField.bool, "Reserved",                 16, nil, 0xc000},
}
local compr_method_def = {ProtoField.uint16, base.HEX, {
    [0] = "Store",
    [8] = "Deflate",
    [12] = "BZIP2",
    [14] = "LZMA (EFS)",
}}
local version_made_def = {
    _ = {ProtoField.none, "Creator version"},
    system      = {ProtoField.uint8, "System", base.DEC, {
        [0] = "MS-DOS and OS/2 (FAT / VFAT / FAT32 file systems)",
        [1] = "Amiga",
        [2] = "OpenVMS",
        [3] = "UNIX",
        [4] = "VM/CMS",
        [5] = "Atari ST",
        [6] = "OS/2 H.P.F.S.",
        [7] = "Macintosh",
        [8] = "Z-System",
        [9] = "CP/M",
        [10] = "Windows NTFS",
        [11] = "MVS (OS/390 - Z/OS)",
        [12] = "VSE",
        [13] = "Acorn Risc",
        [14] = "VFAT",
        [15] = "alternate MVS",
        [16] = "BeOS",
        [17] = "Tandem",
        [18] = "OS/400",
        [19] = "OS X (Darwin)",
    }},
    spec        = {ProtoField.uint8, "Supported ZIP specification version"},
}
local version_req_def = {
    _ = {ProtoField.none, "Version needed to extract"},
    system      = version_made_def.system,
    spec        = {ProtoField.uint8, "Required ZIP specification version"}
}
local attr_extern_def = {
    _ = {ProtoField.uint32, "External file attributes", base.HEX},
    file_mode       = {ProtoField.uint16, "File mode", base.OCT},
}
local extra_def = {
    _ = {ProtoField.none, "Extensible data fields"},
    header_id       = {ProtoField.uint16, base.HEX, {
        [0x5455] = "Extended timestamp",
        [0x7875] = "Unix UID/GIDs",
        [0xcafe] = "Jar magic number", -- see java/util/jar/JarOutputStream.java
    }},
    data_size       = {ProtoField.uint16, base.DEC},
    data            = {ProtoField.bytes},
}
make_fields("zip_archive", {
    signature = {ProtoField.uint32, base.HEX},
    entry = {
        _ = {ProtoField.none, "File entry"},
        version_req     = version_req_def,
        flag            = general_purpose_flags_def,
        comp_method     = compr_method_def,
        lastmod_time    = {ProtoField.uint16, base.HEX},
        lastmod_date    = {ProtoField.uint16, base.HEX},
        crc32           = {ProtoField.uint32, base.HEX},
        size_comp       = {ProtoField.uint32, base.DEC},
        size_uncomp     = {ProtoField.uint32, base.DEC},
        filename_len    = {ProtoField.uint16, base.DEC},
        extra_len       = {ProtoField.uint16, base.DEC},
        filename        = {ProtoField.string},
        extra           = extra_def,
        data            = {ProtoField.bytes},
        data_uncomp     = {ProtoField.bytes},
        data_desc = {
            _ = {ProtoField.none, "Data descriptor"},
            crc32           = {ProtoField.uint32, base.HEX},
            size_comp       = {ProtoField.uint32, base.DEC},
            size_uncomp     = {ProtoField.uint32, base.DEC},
        },
    },
    cd = {
        _ = {ProtoField.none, "Central Directory Record"},
        version_made    = version_made_def,
        version_req     = version_req_def,
        flag            = general_purpose_flags_def,
        comp_method     = compr_method_def,
        lastmod_time    = {ProtoField.uint16, base.HEX},
        lastmod_date    = {ProtoField.uint16, base.HEX},
        crc32           = {ProtoField.uint32, base.HEX},
        size_comp       = {ProtoField.uint32, base.DEC},
        size_uncomp     = {ProtoField.uint32, base.DEC},
        filename_len    = {ProtoField.uint16, base.DEC},
        extra_len       = {ProtoField.uint16, base.DEC},
        comment_len     = {ProtoField.uint16, base.DEC},
        disk_number     = {ProtoField.uint16, base.DEC},
        attr_intern     = {ProtoField.uint16, base.HEX},
        attr_extern     = attr_extern_def,
        relative_offset = {ProtoField.uint32, base.HEX_DEC},
        filename        = {ProtoField.string},
        extra           = extra_def,
        comment         = {ProtoField.string},
    },
    eocd = {
        _ = {ProtoField.none, "End of Central Directory Record"},
        disk_number     = {ProtoField.uint16, base.DEC},
        disk_start      = {ProtoField.uint16, base.DEC},
        num_entries     = {ProtoField.uint16, base.DEC},
        num_entries_total = {ProtoField.uint16, base.DEC},
        size            = {ProtoField.uint32, base.DEC},
        relative_offset = {ProtoField.uint32, base.HEX_DEC},
        comment_len     = {ProtoField.uint16, base.DEC},
    },
}, hf, proto_zip.fields)

--[[ This can be used when implementing a "proper" program.
--
-- Parse Zip Archive as follows:
-- 1. Find EOCD, obtain CD offset and length
-- 2. Find first CD. Then for each CD:
-- 2a. Obtain Local File Header offset and data size.
-- 2b. Find Local File Header.
-- ...
--
local function find_eocd(tvb)
    if tvb(0, 4):le_uint() ~= 0x06054b50 then
        -- Magic not found... possibly comment present
        return
    end
    return {
        offset = tvb(16, 4):le_uint(),
        length = tvb(12, 4):le_uint(),
    }
end
--]]

-- Returns the length of the data and the length of the data descriptor.
local function find_data_desc(tvb)
    local dd_offset = 0
    local data = tvb:raw(tvb:offset())
    -- Scans (byte for byte) for the size field and try to confirm the validity
    -- of this length field. It might still have a false positive, but at least
    -- it allows for a linear scan through the file (without consulting CD).
    while dd_offset + 16 <= #data do
        -- Try to locate the begin of the Data descriptor header (dd_offset).
        -- Assume no signature, so begin is at CRC-32 and size is next dword.
        -- If there is actually a signature, then dd_offset-4 is the begin.
        local comp_size = Struct.unpack("<I4", data, dd_offset + 5)
        if comp_size == dd_offset - 4 and
            Struct.unpack("<I4", data, dd_offset - 3) == 0x08074b50 then
            -- Signature found, data ends four bytes ago.
            return dd_offset - 4, 16
        elseif comp_size == dd_offset then
            -- Signature not found, but length matches.
            return dd_offset, 12
        else
            -- Continue with next byte.
            dd_offset = dd_offset + 1
        end
    end
end

local function dissect_version(hfs, tvb, tree)
    local ti = tree:add_le(hfs._, tvb)
    local spec_version = tvb(0, 1):uint()
    ti:add(hfs.spec,        tvb(0, 1)):append_text(string.format(" (%d.%d)",
        spec_version / 10, spec_version % 10))
    ti:add(hfs.system,      tvb(1, 1))
end

local function dissect_flags(hfs, tvb, tree)
    local flgtree = tree:add_le(hfs._,  tvb)
    -- TODO why does flag.has_data_desc segfault if tvb is not given?
    flgtree:add_le(hfs.encrypted,       tvb)
    flgtree:add_le(hfs.comp_option,     tvb)
    flgtree:add_le(hfs.has_data_desc,   tvb)
    flgtree:add_le(hfs.enhanced_deflate,tvb)
    flgtree:add_le(hfs.compr_patched,   tvb)
    flgtree:add_le(hfs.strong_encrypt,  tvb)
    flgtree:add_le(hfs.unused,          tvb)
    flgtree:add_le(hfs.lang_encoding,   tvb)
    flgtree:add_le(hfs.enhanced_compr,  tvb)
    flgtree:add_le(hfs.hdr_data_masked, tvb)
    flgtree:add_le(hfs.reserved,        tvb)
end

local function dissect_extern_attr(hfs, tvb, tree, os_version)
    local ti = tree:add_le(hfs._, tvb)
    if os_version == 3 then -- Unix
        -- Info-ZIP stores file mode in higher bits (see unix/unix.c)
        ti:add_le(hfs.file_mode,            tvb(2, 2))
    end
end

local function dissect_extra(hfs, tvb, tree)
    local etree = tree:add(hfs._, tvb)
    local offset, length = 0, tvb:len()
    while offset + 4 <= length do
        etree:add_le(hfs.header_id,         tvb(offset, 2))
        etree:add_le(hfs.data_size,         tvb(offset + 2, 2))
        local data_size = tvb(offset + 2, 2):le_uint()
        if data_size > 0 then
            etree:add_le(hfs.data,              tvb(offset + 4, data_size))
        end
        offset = offset + 4 + data_size
    end
end

local function dissect_one(tvb, offset, pinfo, tree)
    local orig_offset = offset
    local magic = tvb(offset, 4):le_int()
    if magic == 0x04034b50 then -- File entry
        local subtree = tree:add_le(hf.entry._, tvb(offset, 30))
        -- header
        subtree:add_le(hf.signature,            tvb(offset, 4))
        dissect_version(hf.entry.version_req,   tvb(offset + 4, 2), subtree)
        dissect_flags(hf.entry.flag,            tvb(offset + 6, 2), subtree)
        subtree:add_le(hf.entry.comp_method,    tvb(offset + 8, 2))
        subtree:add_le(hf.entry.lastmod_time,   tvb(offset + 10, 2))
        subtree:add_le(hf.entry.lastmod_date,   tvb(offset + 12, 2))
        subtree:add_le(hf.entry.crc32,          tvb(offset + 14, 4))
        subtree:add_le(hf.entry.size_comp,      tvb(offset + 18, 4))
        subtree:add_le(hf.entry.size_uncomp,    tvb(offset + 22, 4))
        subtree:add_le(hf.entry.filename_len,   tvb(offset + 26, 2))
        subtree:add_le(hf.entry.extra_len,      tvb(offset + 28, 2))
        local comp_method = tvb(offset + 8, 2):le_uint()
        local flag = tvb(offset + 6, 2):le_uint()
        local data_len = tvb(offset + 18, 4):le_uint()
        local filename_len = tvb(offset + 26, 2):le_uint()
        local extra_len = tvb(offset + 28, 2):le_uint()

        -- Optional data descriptor follows data if GP flag bit 3 (0x8) is set
        local ddlen
        if bit.band(flag, 8) ~= 0 then
            local data_offset = offset + 30 + filename_len + extra_len
            data_len, ddlen = find_data_desc(tvb(data_offset))
        end

        -- skip header
        offset = offset + 30
        subtree:add(hf.entry.filename,          tvb(offset, filename_len))
        subtree:append_text(": " .. tvb(offset, filename_len):string())
        offset = offset + filename_len
        if extra_len > 0 then
            dissect_extra(hf.entry.extra,       tvb(offset, extra_len), subtree)
            offset = offset + extra_len
        end
        if data_len and data_len > 0 then
            subtree:add(hf.entry.data,          tvb(offset, data_len))
            -- Try to decompress Deflate (if allowed)
            if proto_zip.prefs.decompress and comp_method == 8 then
                local data_tvb = tvb(offset, data_len):uncompress("Decompressed data")
                if data_tvb then
                    subtree:add(hf.entry.data_uncomp, data_tvb)
                end
            end
            offset = offset + data_len
        end
        -- Optional data descriptor header
        if ddlen then
            local dd_offset = offset
            local ddtree = subtree:add_le(hf.entry.data_desc._, tvb(dd_offset, ddlen))
            if ddlen == 16 then
                ddtree:add_le(hf.signature,                 tvb(dd_offset, 4))
                dd_offset = dd_offset + 4
            end
            ddtree:add_le(hf.entry.data_desc.crc32,         tvb(dd_offset, 4))
            ddtree:add_le(hf.entry.data_desc.size_comp,     tvb(dd_offset + 4, 4))
            ddtree:add_le(hf.entry.data_desc.size_uncomp,   tvb(dd_offset + 8, 4))
            offset = offset + ddlen
        end

        subtree:set_len(offset - orig_offset)
        return offset
    elseif magic == 0x02014b50 then -- Central Directory
        local subtree = tree:add_le(hf.cd._,    tvb(offset, 46))
        subtree:add_le(hf.signature,            tvb(offset, 2))
        dissect_version(hf.cd.version_made,     tvb(offset + 4, 2), subtree)
        dissect_version(hf.cd.version_req,      tvb(offset + 6, 2), subtree)
        dissect_flags(hf.cd.flag,               tvb(offset + 8, 2), subtree)
        subtree:add_le(hf.cd.comp_method,       tvb(offset + 10, 2))
        subtree:add_le(hf.cd.lastmod_time,      tvb(offset + 12, 2))
        subtree:add_le(hf.cd.lastmod_date,      tvb(offset + 14, 2))
        subtree:add_le(hf.cd.crc32,             tvb(offset + 16, 4))
        subtree:add_le(hf.cd.size_comp,         tvb(offset + 20, 4))
        subtree:add_le(hf.cd.size_uncomp,       tvb(offset + 24, 4))
        subtree:add_le(hf.cd.filename_len,      tvb(offset + 28, 2))
        subtree:add_le(hf.cd.extra_len,         tvb(offset + 30, 2))
        subtree:add_le(hf.cd.comment_len,       tvb(offset + 32, 2))
        subtree:add_le(hf.cd.disk_number,       tvb(offset + 34, 2))
        subtree:add_le(hf.cd.attr_intern,       tvb(offset + 36, 2))
        dissect_extern_attr(hf.cd.attr_extern,  tvb(offset + 38, 4), subtree, tvb(offset + 5, 1):le_uint())
        subtree:add_le(hf.cd.relative_offset,   tvb(offset + 42, 4))

        local filename_len = tvb(offset + 28, 2):le_uint()
        local extra_len = tvb(offset + 30, 2):le_uint()
        local comment_len = tvb(offset + 32, 2):le_uint()
        -- skip header
        offset = offset + 46
        subtree:add(hf.cd.filename,             tvb(offset, filename_len))
        subtree:append_text(": " .. tvb(offset, filename_len):string())
        offset = offset + filename_len
        if extra_len > 0 then
            dissect_extra(hf.cd.extra,          tvb(offset, extra_len), subtree)
            offset = offset + extra_len
        end
        if comment_len > 0 then
            subtree:add(hf.cd.comment,          tvb(offset, comment_len))
            offset = offset + comment_len
        end
        subtree:set_len(offset - orig_offset)
        return offset
    elseif magic == 0x06054b50 then -- End of Central Directory
        local subtree = tree:add_le(hf.cd._,    tvb(offset, 22))
        subtree:add_le(hf.signature,            tvb(offset, 4))
        subtree:add_le(hf.eocd.disk_number,     tvb(offset + 4, 2))
        subtree:add_le(hf.eocd.disk_start,      tvb(offset + 6, 2))
        subtree:add_le(hf.eocd.num_entries,     tvb(offset + 8, 2))
        subtree:add_le(hf.eocd.num_entries_total, tvb(offset + 10, 2))
        subtree:add_le(hf.eocd.size,            tvb(offset + 12, 4))
        subtree:add_le(hf.eocd.relative_offset, tvb(offset + 16, 4))
        subtree:add_le(hf.eocd.comment_len,     tvb(offset + 20, 2))

        local comment_len = tvb(offset + 20, 2):le_uint()
        offset = offset + 22
        if comment_len > 0 then
            subtree:add(hf.eocd.comment,        tvb(offset, comment_len))
            offset = offset + comment_len
        end
        subtree:set_len(offset - orig_offset)
        return offset
    elseif tvb:raw(offset, 2) == "PK" then
        -- Unknown signature
        tree:add_le(hf.signature, tvb(offset, 4))
    end
end

function proto_zip.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "zip"
    --pinfo.cols.info = ""

    local next_offset = 0
    while next_offset and next_offset < tvb:len() do
        next_offset = dissect_one(tvb, next_offset, pinfo, tree)
    end
    return next_offset
end

local function zip_heur(tvb, pinfo, tree)
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
