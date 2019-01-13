--
-- Tar dissector
-- Author: Peter Wu <peter@lekensteyn.nl>
--
-- Information about the file format:
-- https://www.gnu.org/software/tar/manual/html_node/Standard.html
-- https://en.wikipedia.org/wiki/Tar_(computing)
--
-- Requires at least Wireshark 2.4 (due to the use of ftypes.CHAR)
--

--
-- Dissection of Tar file contents
--

--[[

// From https://www.gnu.org/software/tar/manual/html_node/Standard.html
struct posix_header
{                              /* byte offset */
  char name[100];               /*   0 */
  char mode[8];                 /* 100 */
  char uid[8];                  /* 108 */
  char gid[8];                  /* 116 */
  char size[12];                /* 124 */
  char mtime[12];               /* 136 */
  char chksum[8];               /* 148 */
  char typeflag;                /* 156 */
  char linkname[100];           /* 157 */
  char magic[6];                /* 257 */
  char version[2];              /* 263 */
  char uname[32];               /* 265 */
  char gname[32];               /* 297 */
  char devmajor[8];             /* 329 */
  char devminor[8];             /* 337 */
  char prefix[155];             /* 345 */
                                /* 500 */
};

# Convert above headers to <name> <offset> <length>
fields=$(xsel | sed -re 's# *char ([a-z]+)\[([0-9]+)\]; */\* +([0-9]+) *\*/#\1 \3 \2#' -e 's# *char ([a-z]+); */\* +([0-9]+) *\*/#\1 \2 1#')
# Convert to hf definitions (and fixup mtime and typeflag)
echo "$fields" | awk '{ printf "    %-12s= ProtoField.string(\"tar.%s\", \"%s\"),\n", $1, $1, $1 }'
# Convert to dissection calls.
echo "$fields" | awk '{ printf "    htree:add(hf.%-10s tvb(offset + %d, %d))\n", $1",", $2, $3 }'
--]]

local typeflag_values = {
    [0] = "Regular file",
    [string.byte("0")] = "Regular file",
    [string.byte("1")] = "Hard link",
    [string.byte("2")] = "Symbolic link",
    [string.byte("3")] = "Character special",
    [string.byte("4")] = "Block special",
    [string.byte("5")] = "Directory",
    [string.byte("6")] = "FIFO special",
    [string.byte("7")] = "Reserved",
    [string.byte("g")] = "Global extended header",
    [string.byte("x")] = "Extended header",
}

local proto_tar = Proto.new("tar_archive", "Tar Archive")
local hf = {
    header      = ProtoField.none("tar.header", "POSIX header"),
    file_data   = ProtoField.bytes("tar.file_data", "File data"),
    -- posix_header
    name        = ProtoField.string("tar.name", "name"),
    mode        = ProtoField.string("tar.mode", "mode"),
    uid         = ProtoField.string("tar.uid", "uid"),
    gid         = ProtoField.string("tar.gid", "gid"),
    size        = ProtoField.string("tar.size", "size"),
    --mtime       = ProtoField.string("tar.mtime", "mtime"),
    mtime       = ProtoField.absolute_time("tar.mtime", "mtime", base.UTC),
    chksum      = ProtoField.string("tar.chksum", "chksum"),
    typeflag    = ProtoField.new("typeflag", "tar.typeflag", ftypes.CHAR, typeflag_values),
    linkname    = ProtoField.string("tar.linkname", "linkname"),
    magic       = ProtoField.string("tar.magic", "magic"),
    version     = ProtoField.string("tar.version", "version"),
    uname       = ProtoField.string("tar.uname", "uname"),
    gname       = ProtoField.string("tar.gname", "gname"),
    devmajor    = ProtoField.string("tar.devmajor", "devmajor"),
    devminor    = ProtoField.string("tar.devminor", "devminor"),
    prefix      = ProtoField.string("tar.prefix", "prefix"),
}
proto_tar.fields = hf

local function dissect_one(tvb, offset, pinfo, tree)
    local htree = tree:add(hf.header, tvb(offset, 500))
    htree:add(hf.name,      tvb(offset + 0, 100))
    local name = tvb:raw(offset, 100):gsub("\0+$", "")
    htree:append_text(string.format(" %s", name))
    htree:add(hf.mode,      tvb(offset + 100, 8))
    htree:add(hf.uid,       tvb(offset + 108, 8))
    htree:add(hf.gid,       tvb(offset + 116, 8))
    htree:add(hf.size,      tvb(offset + 124, 12))
    local mtime = tonumber(tvb:raw(offset + 136, 12):gsub("\0+$", ""), 8)
    htree:add(hf.mtime,     tvb(offset + 136, 12), NSTime(mtime))
    htree:add(hf.chksum,    tvb(offset + 148, 8))
    htree:add(hf.typeflag,  tvb(offset + 156, 1))
    local ftype = typeflag_values[tvb(offset + 156, 1):uint()]
    if ftype then htree:append_text(string.format(" (%s)", ftype)) end
    htree:add(hf.linkname,  tvb(offset + 157, 100))
    htree:add(hf.magic,     tvb(offset + 257, 6))
    htree:add(hf.version,   tvb(offset + 263, 2))
    htree:add(hf.uname,     tvb(offset + 265, 32))
    htree:add(hf.gname,     tvb(offset + 297, 32))
    htree:add(hf.devmajor,  tvb(offset + 329, 8))
    htree:add(hf.devminor,  tvb(offset + 337, 8))
    htree:add(hf.prefix,    tvb(offset + 345, 155))

    local size = tonumber(tvb:raw(offset + 124, 12):gsub("\0+$", ""), 8)
    offset = offset + 512
    if size and size > 0 then
        htree:append_text(string.format(" (%d bytes)", size))
        tree:add(hf.file_data, tvb(offset, size))
        offset = offset + size
    end
    if offset % 512 ~= 0 then
        offset = offset - (offset % 512) + 512
    end
    -- Detect end of archive (at least two consecutive zero-filled records).
    while offset + 512 <= tvb:len() and tvb:raw(offset, 500):match("^\0+$") do
        offset = offset + 512
    end
    return offset
end

function proto_tar.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "tar"
    --pinfo.cols.info = ""

    local next_offset = 0
    while next_offset and next_offset < tvb:len() do
        next_offset = dissect_one(tvb, next_offset, pinfo, tree)
    end
    return next_offset
end

local function tar_heur(tvb, pinfo, tree)
    if tvb:len() < 512 or tvb:raw(257, 6) ~= "ustar\0" then
        return false
    end

    proto_tar.dissector(tvb, pinfo, tree)
    return true
end

-- Register MIME types in case a Tar file appears over HTTP.
DissectorTable.get("media_type"):add("application/x-tar", proto_tar)

-- Ensure that files can directly be opened (after any FileHandler has accepted
-- it, see below).
proto_tar:register_heuristic("wtap_file", tar_heur)


--
-- File handler (for directly interpreting opening a Tar file in Wireshark)
-- Actually, all it does is recognizing a Tar file and passing one packet to the
-- MIME dissector.
--

local tar_fh = FileHandler.new("Tar", "tar", "Tar archive file reader", "rms")

-- Check if file is really a tar file (return true if it is)
function tar_fh.read_open(file, cinfo)
    -- Detect UStar format
    if not (file:seek("set", 257) and file:read(6) == "ustar\0") then
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
local function tar_fh_read(file, cinfo, finfo)
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
tar_fh.read = tar_fh_read

-- Reads packet at offset (returns true on success and false on failure)
function tar_fh.seek_read(file, cinfo, finfo, offset)
    file:seek("set", offset)
    -- Return a boolean since WS < 2.4 has an undocumented "feature" where
    -- strings (including numbers) are treated as data.
    return tar_fh_read(file, cinfo, finfo) ~= false
end

-- Hints for when to invoke this dissector.
tar_fh.extensions = "tar"

register_filehandler(tar_fh)
