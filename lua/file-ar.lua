--
-- ar (Unix) dissector
-- Author: Peter Wu <peter@lekensteyn.nl>
--
-- Information about the file format:
-- https://en.wikipedia.org/wiki/Ar_(Unix)#File_format_details
-- https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#archive-library-file-format
--

-- More are defined at https://docs.microsoft.com/en-us/windows/desktop/Debug/pe-format#machine-types
local machine_types = {
    [0x0000] = "Unknown",
    [0x014c] = "i386",
    [0x8664] = "x64",
}
local import_types = {
    [0] = "IMPORT_CODE",
    [1] = "IMPORT_DATA",
    [2] = "IMPORT_CONST",
}
local import_name_types = {
    [0] = "IMPORT_ORDINAL",
    [1] = "IMPORT_NAME",
    [2] = "IMPORT_NAME_NOPREFIX",
    [3] = "IMPORT_NAME_UNDECORATE",
}
local reloc_types_x64 = {
    [0x0000] = "IMAGE_REL_AMD64_ABSOLUTE",
    [0x0001] = "IMAGE_REL_AMD64_ADDR64",
    [0x0002] = "IMAGE_REL_AMD64_ADDR32",
    [0x0003] = "IMAGE_REL_AMD64_ADDR32NB",
    [0x0004] = "IMAGE_REL_AMD64_REL32",
    [0x0005] = "IMAGE_REL_AMD64_REL32_1",
    [0x0006] = "IMAGE_REL_AMD64_REL32_2",
    [0x0007] = "IMAGE_REL_AMD64_REL32_3",
    [0x0008] = "IMAGE_REL_AMD64_REL32_4",
    [0x0009] = "IMAGE_REL_AMD64_REL32_5",
    [0x000A] = "IMAGE_REL_AMD64_SECTION",
    [0x000B] = "IMAGE_REL_AMD64_SECREL",
    [0x000C] = "IMAGE_REL_AMD64_SECREL7",
    [0x000D] = "IMAGE_REL_AMD64_TOKEN",
    [0x000E] = "IMAGE_REL_AMD64_SREL32",
    [0x000F] = "IMAGE_REL_AMD64_PAIR",
    [0x0010] = "IMAGE_REL_AMD64_SSPAN32",
}
local storage_classes = {
    [255] = "IMAGE_SYM_CLASS_END_OF_FUNCTION",
    [0] = "IMAGE_SYM_CLASS_NULL",
    [1] = "IMAGE_SYM_CLASS_AUTOMATIC",
    [2] = "IMAGE_SYM_CLASS_EXTERNAL",
    [3] = "IMAGE_SYM_CLASS_STATIC",
    [4] = "IMAGE_SYM_CLASS_REGISTER",
    [5] = "IMAGE_SYM_CLASS_EXTERNAL_DEF",
    [6] = "IMAGE_SYM_CLASS_LABEL",
    [7] = "IMAGE_SYM_CLASS_UNDEFINED_LABEL",
    [8] = "IMAGE_SYM_CLASS_MEMBER_OF_STRUCT",
    [9] = "IMAGE_SYM_CLASS_ARGUMENT",
    [10] = "IMAGE_SYM_CLASS_STRUCT_TAG",
    [11] = "IMAGE_SYM_CLASS_MEMBER_OF_UNION",
    [12] = "IMAGE_SYM_CLASS_UNION_TAG",
    [13] = "IMAGE_SYM_CLASS_TYPE_DEFINITION",
    [14] = "IMAGE_SYM_CLASS_UNDEFINED_STATIC",
    [15] = "IMAGE_SYM_CLASS_ENUM_TAG",
    [16] = "IMAGE_SYM_CLASS_MEMBER_OF_ENUM",
    [17] = "IMAGE_SYM_CLASS_REGISTER_PARAM",
    [18] = "IMAGE_SYM_CLASS_BIT_FIELD",
    [100] = "IMAGE_SYM_CLASS_BLOCK",
    [101] = "IMAGE_SYM_CLASS_FUNCTION",
    [102] = "IMAGE_SYM_CLASS_END_OF_STRUCT",
    [103] = "IMAGE_SYM_CLASS_FILE",
    [104] = "IMAGE_SYM_CLASS_SECTION",
    [105] = "IMAGE_SYM_CLASS_WEAK_EXTERNAL",
    [107] = "IMAGE_SYM_CLASS_CLR_TOKEN",
}
local subsystem_values = {
    [0] = "IMAGE_SUBSYSTEM_UNKNOWN",
    [1] = "IMAGE_SUBSYSTEM_NATIVE",
    [2] = "IMAGE_SUBSYSTEM_WINDOWS_GUI",
    [3] = "IMAGE_SUBSYSTEM_WINDOWS_CUI",
    [5] = "IMAGE_SUBSYSTEM_OS2_CUI",
    [7] = "IMAGE_SUBSYSTEM_POSIX_CUI",
    [8] = "IMAGE_SUBSYSTEM_NATIVE_WINDOWS",
    [9] = "IMAGE_SUBSYSTEM_WINDOWS_CE_GUI",
    [10] = "IMAGE_SUBSYSTEM_EFI_APPLICATION",
    [11] = "IMAGE_SUBSYSTEM_EFI_BOOT_",
    [12] = "IMAGE_SUBSYSTEM_EFI_RUNTIME_",
    [13] = "IMAGE_SUBSYSTEM_EFI_ROM",
    [14] = "IMAGE_SUBSYSTEM_XBOX",
    [16] = "IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION",
}

local proto_ar = Proto.new("ar_archive", "ar Archive")
local hf = {
    header      = ProtoField.none("ar.header", "Archive Header"),
    magic       = ProtoField.string("ar.magic", "Magic"),
    entry       = ProtoField.none("ar.entry", "File entry"),
    file_id     = ProtoField.string("ar.file_id", "File identifier"),
    file_mtime  = ProtoField.absolute_time("ar.file_mtime", "File modification timestamp", base.UTC),
    owner_id    = ProtoField.string("ar.owner_id", "Owner ID"),
    group_id    = ProtoField.string("ar.group_id", "Group ID"),
    file_mode   = ProtoField.string("ar.file_mode", "File mode"),
    file_size   = ProtoField.string("ar.file_size", "File size"),
    end_chars   = ProtoField.string("ar.end_chars", "End of header"),
    file_data   = ProtoField.bytes("ar.file_data", "File data"),
    padding     = ProtoField.bytes("ar.padding", "Padding"),
    l1_number_of_symbols = ProtoField.uint32("ar.l1.number_of_symbols", "Number of Symbols"),
    l1_file_offset  = ProtoField.uint32("ar.l1.file_offset", "File offset", base.HEX_DEC),
    l1_symbol_name  = ProtoField.stringz("ar.l1.symbol_name", "Symbol Name"),
    l2_number_of_members = ProtoField.uint32("ar.l2.number_of_members", "Number of Members"),
    l2_number_of_symbols = ProtoField.uint32("ar.l2.number_of_symbols", "Number of Symbols"),
    l2_file_offset  = ProtoField.uint32("ar.l2.file_offset", "File offset", base.HEX_DEC, nil, nil, "File offset to archive member headers"),
    l2_index        = ProtoField.uint32("ar.l2.index", "Index", base.DEC, nil, nil, "Index into offsets array"),
    l2_symbol_name  = ProtoField.stringz("ar.l2.symbol_name", "Symbol Name"),
    ln_member_name  = ProtoField.string("ar.ln.member_name", "Member Name"),
    import_header      = ProtoField.none("ar.import_header", "Import Header"),
    imp_sig1        = ProtoField.none("ar.imp.sig1", "Import Header Sig1"),
    imp_sig2        = ProtoField.none("ar.imp.sig1", "Import Header Sig2"),
    imp_version     = ProtoField.uint16("ar.imp.version", "Structure Version"),
    imp_machine     = ProtoField.uint16("ar.imp.machine", "Machine Type", base.HEX, machine_types),
    imp_timedate    = ProtoField.absolute_time("ar.imp.timedate", "Creation Datetime", base.UTC),
    imp_size        = ProtoField.uint32("ar.imp.size", "Size"),
    imp_hint        = ProtoField.uint16("ar.imp.hint", "Ordinal/Hint"),
    imp_type        = ProtoField.uint16("ar.imp.type", "Import Type", base.DEC, import_types, 0x0003),
    imp_name_type   = ProtoField.uint16("ar.imp.name_type", "Import Name Type", base.DEC, import_name_types, 0x000c),
    imp_symbol_name = ProtoField.stringz("ar.imp.symbol_name", "Symbol Name"),
    imp_dll         = ProtoField.stringz("ar.imp.dll", "DLL"),
    coff_file_header        = ProtoField.none("ar.coff.file_header", "COFF File Header"),
    coff_machine            = ProtoField.uint16("ar.coff.machine", "Machine Type", base.HEX, machine_types),
    coff_number_of_sections = ProtoField.uint16("ar.coff.number_of_sections", "Number of sections"),
    coff_timedate           = ProtoField.absolute_time("ar.coff.timedate", "Creation Datetime", base.UTC),
    coff_symbol_table_ptr   = ProtoField.uint32("ar.coff.symbol_table_ptr", "PointerToSymbolTable", base.HEX_DEC),
    coff_number_of_symbols  = ProtoField.uint32("ar.coff.number_of_symbols", "Number of symbols"),
    coff_opt_header_size    = ProtoField.uint16("ar.coff.opt_header_size", "Optional Header Size"),
    coff_characteristics    = ProtoField.uint16("ar.coff.characteristics", "Characteristics", base.HEX),
    coff_section            = ProtoField.none("ar.coff.section", "Section"),
    coff_sect_name          = ProtoField.stringz("ar.coff.sect.name", "Section Name"),
    coff_sect_virtual_size  = ProtoField.uint32("ar.coff.sect.virtual_size", "Virtual Size"),
    coff_sect_virtual_addr  = ProtoField.uint32("ar.coff.sect.virtual_addr", "Virtual Address"),
    coff_sect_size          = ProtoField.uint32("ar.coff.sect.size", "Raw Data Size"),
    coff_sect_raw_data_ptr  = ProtoField.uint32("ar.coff.sect.raw_data_ptr", "PointerToRawData", base.HEX_DEC),
    coff_sect_relocs_ptr    = ProtoField.uint32("ar.coff.sect.relocs_ptr", "PointerToRelocations", base.HEX_DEC),
    coff_sect_linenums_ptr  = ProtoField.uint32("ar.coff.sect.linenums_ptr", "PointerToLinenumbers", base.HEX_DEC),
    coff_sect_number_of_relocs = ProtoField.uint16("ar.coff.sect.number_of_relocs", "Number of relocations"),
    coff_sect_number_of_linenums = ProtoField.uint16("ar.coff.sect.number_of_linenums", "Number of line numbers"),
    coff_sect_characteristics = ProtoField.uint32("ar.coff.sect.characteristics", "Characteristics", base.HEX),
    coff_sect_data          = ProtoField.bytes("ar.coff.sect.data", "Section Data"),
    coff_reloc              = ProtoField.none("ar.coff.reloc", "COFF Relocation"),
    coff_reloc_virtual_addr = ProtoField.uint32("ar.coff.virtual_addr", "Virtual Address", base.HEX_DEC),
    coff_reloc_symbol_table_index = ProtoField.uint32("ar.coff.symbol_table_index", "Symbol Table Index", base.HEX_DEC),
    coff_reloc_type         = ProtoField.uint16("ar.coff.type", "Relocation Type", base.HEX),
    coff_reloc_type_x64     = ProtoField.uint16("ar.coff.type.x64", "Relocation Type", base.HEX, reloc_types_x64),
    coff_sym                = ProtoField.none("ar.coff.sym", "COFF Symbol Table Entry"),
    coff_sym_shortname      = ProtoField.string("ar.coff.sym.shortname", "Symbol Name"),
    coff_sym_name           = ProtoField.stringz("ar.coff.sym.name", "Symbol Name"),
    coff_sym_name_zeroes    = ProtoField.none("ar.coff.sym.name.zeroes", "Zeroes"),
    coff_sym_name_offset    = ProtoField.uint32("ar.coff.sym.name.offset", "Offset"),
    coff_sym_value          = ProtoField.uint32("ar.coff.sym.value", "Value", base.HEX_DEC),
    coff_sym_section_number = ProtoField.uint16("ar.coff.sym.section_number", "Section Number"),
    coff_sym_type           = ProtoField.uint16("ar.coff.sym.type", "Type", base.HEX, {[0] = "not a function", [0x20] = "function"}),
    coff_sym_storage_class  = ProtoField.uint8("ar.coff.sym.storage_class", "Storage Class", base.DEC, storage_classes),
    coff_sym_number_of_aux_symbols = ProtoField.uint8("ar.coff.sym.number_of_aux_symbols", "Number of auxilliary symbols"),

    -- XXX expert info?
    unprocessed = ProtoField.bytes("ar.unprocessed", "Unprocessed Data"),
}
proto_ar.fields = hf

local proto_pe = Proto.new("pe", "Portable Executablear Archive")
local pe_hf = {
    dos                 = ProtoField.none("pe.dos", "DOS Header"),
    dos_magic           = ProtoField.none("pe.dos.magic", "DOS .EXE header"),
    dos_lfanew          = ProtoField.uint32("pe.dos.lfanew", "File address of new exe header", base.HEX_DEC),
    dos_stub            = ProtoField.bytes("pe.dos.stub", "DOS Stub"),
    magic               = ProtoField.none("pe.magic", "PE Signature"),
    opth                = ProtoField.none("pe.opth", "Optional Header"),
    opth_standard       = ProtoField.none("pe.opth.standard", "Optional Header Standard Fields"),
    opth_magic          = ProtoField.uint16("pe.opth.magic", "Magic", base.HEX, {[0x10b] = "PE32", [0x20b] = "PE32+"}),
    opth_major_linker_version = ProtoField.uint8("pe.opth.major_linker_version", "Major Linker Version"),
    opth_minor_linker_version = ProtoField.uint8("pe.opth.major_linker_version", "Major Linker Version"),
    opth_size_of_code   = ProtoField.uint32("pe.opth.size_of_code", "Size of code sections"),
    opth_size_of_data   = ProtoField.uint32("pe.opth.size_of_data", "Size of data sections"),
    opth_size_of_bss    = ProtoField.uint32("pe.opth.size_of_bss", "Size of BSS sections"),
    opth_entrypoint     = ProtoField.uint32("pe.opth.entrypoint", "Address of entry point", base.HEX),
    opth_base_of_code   = ProtoField.uint32("pe.opth.base_of_code", "BaseOfCode", base.HEX),
    opth_base_of_data   = ProtoField.uint32("pe.opth.base_of_data", "BaseOfData", base.HEX),
    opth_windows_specific   = ProtoField.none("pe.opth.windows_specific", "Optional Header Windows-Specific Fields"),
    opth_image_base         = ProtoField.uint64("pe.opth.image_base", "ImageBase", base.HEX),
    opth_section_alignment  = ProtoField.uint16("pe.opth.section_alignment", "SectionAlignment", base.HEX_DEC),
    opth_file_alignment     = ProtoField.uint16("pe.opth.file_alignment", "FileAlignment", base.HEX_DEC),
    opth_major_osversion    = ProtoField.uint16("pe.opth.major_osversion", "MajorOperatingSystemVersion"),
    opth_minor_osversion    = ProtoField.uint16("pe.opth.minor_osversion", "MinorOperatingSystemVersion"),
    opth_major_imversion    = ProtoField.uint16("pe.opth.major_imversion", "MajorImageVersion"),
    opth_minor_imversion    = ProtoField.uint16("pe.opth.minor_imversion", "MinorImageVersion"),
    opth_major_ssversion    = ProtoField.uint16("pe.opth.major_ssversion", "MajorSubsystemVersion"),
    opth_minor_ssversion    = ProtoField.uint16("pe.opth.minor_ssversion", "MinorSubsystemVersion"),
    opth_win32_version      = ProtoField.uint32("pe.opth.win32_version", "Win32VersionValue "),
    opth_size_of_image      = ProtoField.uint32("pe.opth.size_of_image", "SizeOfImage"),
    opth_size_of_headers    = ProtoField.uint32("pe.opth.size_of_headers", "SizeOfHeaders"),
    opth_checksum           = ProtoField.uint32("pe.opth.checksum", "Checksum", base.HEX),
    opth_subsystem          = ProtoField.uint16("pe.opth.subsystem", "Subsystem", base.DEC, subsystem_values),
    opth_dll_characteristics    = ProtoField.uint16("pe.opth.dll_characteristics", "DllCharacteristics"),
    opth_size_of_stack_reserve  = ProtoField.uint64("pe.opth.size_of_stack_reserve", "SizeOfStackReserve", base.HEX_DEC),
    opth_size_of_stack_commit   = ProtoField.uint64("pe.opth.size_of_stack_commit", "SizeOfStackCommit", base.HEX_DEC),
    opth_size_of_heap_reserve   = ProtoField.uint64("pe.opth.size_of_heap_reserve", "SizeOfHeapReserve", base.HEX_DEC),
    opth_size_of_heap_commit    = ProtoField.uint64("pe.opth.size_of_heap_commit", "SizeOfHeapCommit", base.HEX_DEC),
    opth_loader_flags       = ProtoField.uint32("pe.opth.loader_flags", "LoaderFlags", base.HEX),
    opth_number_of_rva_and_sizes = ProtoField.uint32("pe.opth.number_of_rva_and_sizes", "NumberOfRvaAndSizes"),
    opth_data_directories   = ProtoField.none("pe.opth.data_directories", "Optional Header Data Directories"),
}
proto_pe.fields = pe_hf

local function dissect_coff_first_linker_member(tvb, offset, file_size, tree, symbols_map)
    local number_of_symbols = tvb(offset, 4):uint()
    tree:add(hf.l1_number_of_symbols, tvb(offset, 4))
    offset = offset + 4
    local strings_offset = offset + 4 * number_of_symbols
    for i = 0, number_of_symbols - 1 do
        local str0len = tvb(strings_offset):strsize()
        local str_tvb = tvb(strings_offset, str0len)
        local subtree = tree:add(hf.l1_symbol_name, str_tvb)
        local fileoff_tvb = tvb(offset + 4 * i, 4)
        subtree:add(hf.l1_file_offset, fileoff_tvb)
        strings_offset = strings_offset + str0len

        local file_offset = fileoff_tvb:uint()
        local symbols_list = symbols_map[file_offset]
        if not symbols_list then
            symbols_list = {}
            symbols_map[file_offset] = symbols_list
        end
        table.insert(symbols_list, str_tvb:stringz())
    end
end

local function dissect_coff_second_linker_member(tvb, offset, file_size, tree, symbols_map)
    local number_of_members = tvb(offset, 4):le_uint()
    tree:add_le(hf.l2_number_of_members, tvb(offset, 4))
    offset = offset + 4

    local file_offset = offset
    offset = offset + 4 * number_of_members

    local number_of_symbols = tvb(offset, 4):le_uint()
    tree:add_le(hf.l2_number_of_symbols, tvb(offset, 4))
    offset = offset + 4

    local strings_offset = offset + 2 * number_of_symbols
    for i = 0, number_of_symbols - 1 do
        local str0len = tvb(strings_offset):strsize()
        local str_tvb = tvb(strings_offset, str0len)
        local subtree = tree:add(hf.l2_symbol_name, str_tvb)
        local index_tvb = tvb(offset + 2 * i, 2)
        subtree:add_le(hf.l2_index, index_tvb)
        local fileoff_tvb = tvb(file_offset + 4 * (index_tvb:le_uint() - 1), 4)
        subtree:add_le(hf.l2_file_offset, fileoff_tvb)
        strings_offset = strings_offset + str0len

        local file_offset = fileoff_tvb:le_uint()
        local symbols_list = symbols_map[file_offset]
        if not symbols_list then
            symbols_list = {}
            symbols_map[file_offset] = symbols_list
        end
        table.insert(symbols_list, str_tvb:stringz())
    end
end

local function dissect_coff_longnames_member(tvb, offset, file_size, tree, member_names_map)
    -- According to the Microsoft PE Format documentation, strings are
    -- terminated by a NULL terminator (presumably '\0'). However, llvm-dlltool
    -- (via lib/Object/ArchiveWriter.cpp) ends a member name with "/\n".
    local strings = tvb:raw(offset, file_size)
    local term = "\0"
    local termlen = 1
    if strings:find("/\n", pos, true) then
        term = "/\n"
        termlen = 2
    end
    local pos = 1
    while true do
        local nextpos = strings:find(term, pos, true)
        if not nextpos then
            break
        end
        tree:add(hf.ln_member_name, tvb(offset + pos - 1, nextpos - pos))
        member_names_map[pos - 1] = strings:sub(pos, nextpos - 1)
        pos = nextpos + termlen
    end
end

local function dissect_coff_import_header(tvb, offset, file_size, tree)
    local offset_begin = offset
    local subtree = tree:add(hf.import_header, tvb(offset, 20))
    subtree:add_le(hf.imp_sig1, tvb(offset, 2))
    subtree:add_le(hf.imp_sig2, tvb(offset + 2, 2))
    subtree:add_le(hf.imp_version, tvb(offset + 4, 2))
    subtree:add_le(hf.imp_machine, tvb(offset + 6, 2))
    subtree:add_le(hf.imp_timedate, tvb(offset + 8, 4))
    subtree:add_le(hf.imp_size, tvb(offset + 12, 4))
    local hint_tvb = tvb(offset + 16, 2)
    subtree:add_le(hf.imp_hint, hint_tvb)
    local typeval = tvb(offset + 18, 2):le_uint()
    subtree:add_le(hf.imp_type, tvb(offset + 18, 2))
    subtree:add_le(hf.imp_name_type, tvb(offset + 18, 2))
    offset = offset + 20
    local type_str = import_types[bit32.band(typeval, 3)]
    local name_type_str = import_name_types[bit32.band(bit32.rshift(typeval, 2), 7)]
    local symbol0len = tvb(offset):strsize()
    local symbol0tvb = tvb(offset, symbol0len)
    subtree:add(hf.imp_symbol_name, symbol0tvb)
    offset = offset + symbol0len
    local dll0len = tvb(offset):strsize()
    local dll0tvb = tvb(offset, dll0len)
    subtree:add(hf.imp_dll, dll0tvb)
    offset = offset + dll0len
    subtree:set_text(string.format("Import: %s from %s (%s %s hint=%d)",
        symbol0tvb:stringz(), dll0tvb:stringz(),
        type_str or "UnkType", name_type_str or "UnkNameType",
        hint_tvb:le_uint()))
    --tree:append_text(string.format(" - %s", symbol0tvb:stringz()))
    tree:append_text(string.format(" hint=%d", hint_tvb:le_uint()))
    subtree:set_len(offset - offset_begin)
    return offset
end

local function dissect_coff_reloc(tvb, offset, tree, hf_reloc_type, type_map)
    local subtree = tree:add(hf.coff_reloc, tvb(offset, 10))
    local va_tvb = tvb(offset, 4)
    subtree:add_le(hf.coff_reloc_virtual_addr, va_tvb)
    local symidx_tvb = tvb(offset + 4, 4)
    subtree:add_le(hf.coff_reloc_symbol_table_index, symidx_tvb)
    local type_tvb = tvb(offset + 8, 2)
    subtree:add_le(hf_reloc_type, type_tvb)
    local reloc_type = type_tvb:le_uint()
    if type_map then
        reloc_type = type_map[reloc_type]
    end
    subtree:append_text(string.format(" va=0x%08x %d %s",
        va_tvb:le_uint(), symidx_tvb:le_uint(), reloc_type))
end

local function dissect_coff_section(tvb, offset, tree, machine, section_number, coff_start)
    local subtree = tree:add(hf.coff_section, tvb(offset, 40))
    local name = tvb:raw(offset, 8)
    subtree:add_le(hf.coff_sect_name, tvb(offset, 8))
    subtree:append_text(string.format(" %d: %s", section_number, name))
    subtree:add_le(hf.coff_sect_virtual_size, tvb(offset + 8, 4))
    subtree:add_le(hf.coff_sect_virtual_addr, tvb(offset + 12, 4))
    local data_size = tvb(offset + 16, 4):le_uint()
    subtree:add_le(hf.coff_sect_size, tvb(offset + 16, 4))
    local data_ptr = coff_start + tvb(offset + 20, 4):le_uint()
    subtree:add_le(hf.coff_sect_raw_data_ptr, tvb(offset + 20, 4))
    local reloc_ptr = coff_start + tvb(offset + 24, 4):le_uint()
    subtree:add_le(hf.coff_sect_relocs_ptr, tvb(offset + 24, 4))
    subtree:add_le(hf.coff_sect_linenums_ptr, tvb(offset + 28, 4))
    local number_of_relocs = tvb(offset + 32, 2):le_uint()
    subtree:add_le(hf.coff_sect_number_of_relocs, tvb(offset + 32, 2))
    subtree:add_le(hf.coff_sect_number_of_linenums, tvb(offset + 34, 2))
    subtree:add_le(hf.coff_sect_characteristics, tvb(offset + 36, 4))
    offset = offset + 40
    subtree:add(hf.coff_sect_data, tvb(data_ptr, data_size))
    if relocs_ptr ~= coff_start and number_of_relocs ~= 0 then
        local hf_reloc_type, type_map
        if machine == 0x8664 then
            hf_reloc_type = hf.coff_reloc_type_x64
            type_map = reloc_types_x64
        else
            hf_reloc_type = hf.coff_reloc_type
        end
        subtree:append_text(string.format(" (relocs=%d)", number_of_relocs))
        for i = 0, number_of_relocs - 1 do
            dissect_coff_reloc(tvb, reloc_ptr + 10 * i, subtree, hf_reloc_type, type_map)
        end
    end
    return offset
end

local function dissect_coff_symbol_name(tvb, offset, tree, strings_offset)
    if tvb(offset, 4):le_uint() ~= 0 then
        tree:add_le(hf.coff_sym_shortname, tvb(offset, 8))
        tree:append_text(string.format(": %s", tvb:raw(offset, 8):gsub("\0+$", "")))
    else
        local name_offset_tvb = tvb(offset + 4, 4)
        local name_tvb = tvb(strings_offset + name_offset_tvb:le_uint())
        local nametree = tree:add(hf.coff_sym_name, name_tvb)
        nametree:add_le(hf.coff_sym_name_zeroes, tvb(offset, 4))
        nametree:add_le(hf.coff_sym_name_offset, name_offset_tvb)
        tree:append_text(string.format(": %s", name_tvb:stringz()))
    end
end

local function dissect_coff_symbol_record(tvb, offset, tree, symbol_index, string_table_ptr)
    local subtree = tree:add(hf.coff_sym, tvb(offset, 18))
    subtree:append_text(string.format(" %d", symbol_index))
    dissect_coff_symbol_name(tvb, offset, subtree, string_table_ptr)
    subtree:add_le(hf.coff_sym_value, tvb(offset + 8, 4))
    subtree:add_le(hf.coff_sym_section_number, tvb(offset + 12, 2))
    subtree:add_le(hf.coff_sym_type, tvb(offset + 14, 2))
    subtree:add_le(hf.coff_sym_storage_class, tvb(offset + 16, 1))
    subtree:add_le(hf.coff_sym_number_of_aux_symbols, tvb(offset + 17, 1))
end

local function dissect_pe_optional_header(tvb, offset, opt_header_size, tree)
    local subtree = tree:add(pe_hf.opth, tvb(offset, opt_header_size))
    local magic  = tvb(offset, 2):le_uint()
    local is_pe32 = magic == 0x10b
    local is_pe32p = magic == 0x20b
    if is_pe32 then
        subtree:append_text(" (PE32)")
    elseif is_pe32p then
        subtree:append_text(" (PE32+)")
    end
    -- Fields Common for all COFF implementations.
    local stdtree = subtree:add(pe_hf.opth_standard, tvb(offset, 24))
    stdtree:add_le(pe_hf.opth_magic, tvb(offset, 2))
    stdtree:add_le(pe_hf.opth_major_linker_version, tvb(offset + 2, 1))
    stdtree:add_le(pe_hf.opth_minor_linker_version, tvb(offset + 3, 1))
    stdtree:add_le(pe_hf.opth_size_of_code, tvb(offset + 4, 4))
    stdtree:add_le(pe_hf.opth_size_of_data, tvb(offset + 8, 4))
    stdtree:add_le(pe_hf.opth_size_of_bss, tvb(offset + 12, 4))
    stdtree:add_le(pe_hf.opth_entrypoint, tvb(offset + 16, 4))
    stdtree:add_le(pe_hf.opth_base_of_code, tvb(offset + 20, 4))
    if is_pe32 then
        stdtree:add_le(pe_hf.opth_base_of_data, tvb(offset + 24, 4))
        stdtree:set_len(28)
    end
    if is_pe32 or is_pe32p then
        local psize, winoffset, winlen
        if is_pe32 then
            psize = 4
            winoffset = offset + 28
            winlen = 68
        else
            psize = 8
            winoffset = offset + 24
            winlen = 88
        end
        -- Windows-specific fields
        local wintree = subtree:add(pe_hf.opth_windows_specific, tvb(winoffset, winlen))
        wintree:add_le(pe_hf.opth_image_base, tvb(winoffset, psize))
        wintree:add_le(pe_hf.opth_section_alignment, tvb(offset + 32, 4))
        wintree:add_le(pe_hf.opth_file_alignment, tvb(offset + 36, 4))
        wintree:add_le(pe_hf.opth_major_osversion, tvb(offset + 40, 2))
        wintree:add_le(pe_hf.opth_minor_osversion, tvb(offset + 42, 2))
        wintree:add_le(pe_hf.opth_major_imversion, tvb(offset + 44, 2))
        wintree:add_le(pe_hf.opth_minor_imversion, tvb(offset + 46, 2))
        wintree:add_le(pe_hf.opth_major_ssversion, tvb(offset + 48, 2))
        wintree:add_le(pe_hf.opth_minor_ssversion, tvb(offset + 50, 2))
        wintree:add_le(pe_hf.opth_win32_version, tvb(offset + 52, 4))
        wintree:add_le(pe_hf.opth_size_of_image, tvb(offset + 56, 4))
        wintree:add_le(pe_hf.opth_size_of_headers, tvb(offset + 60, 4))
        wintree:add_le(pe_hf.opth_checksum, tvb(offset + 64, 4))
        wintree:add_le(pe_hf.opth_subsystem, tvb(offset + 68, 2))
        wintree:add_le(pe_hf.opth_dll_characteristics, tvb(offset + 70, 2))
        wintree:add_le(pe_hf.opth_size_of_stack_reserve, tvb(offset + 72, psize))
        wintree:add_le(pe_hf.opth_size_of_stack_commit, tvb(offset  + 72 + psize, psize))
        wintree:add_le(pe_hf.opth_size_of_heap_reserve, tvb(offset + 72 + 2 * psize, psize))
        wintree:add_le(pe_hf.opth_size_of_heap_commit, tvb(offset + 72 + 3 * psize, psize))
        local lf_offset = offset + 72 + 4 * psize
        wintree:add_le(pe_hf.opth_loader_flags, tvb(lf_offset, 4))
        wintree:add_le(pe_hf.opth_number_of_rva_and_sizes, tvb(lf_offset + 4, 4))
        -- Data directories.
        local ddoffset = winoffset + winlen
        subtree:add(pe_hf.opth_data_directories, tvb(ddoffset, 128))
    end
end

local function dissect_coff_file_header(tvb, offset, file_size, tree, coff_start)
    local subtree = tree:add(hf.coff_file_header, tvb(offset, 20))
    local machine = tvb(offset, 2):le_uint()
    subtree:add_le(hf.coff_machine, tvb(offset, 2))
    local number_of_sections = tvb(offset + 2, 2):le_uint()
    subtree:add_le(hf.coff_number_of_sections , tvb(offset + 2, 2))
    subtree:add_le(hf.coff_timedate, tvb(offset + 4, 4))
    local symbol_table_ptr = coff_start + tvb(offset + 8, 4):le_uint()
    subtree:add_le(hf.coff_symbol_table_ptr, tvb(offset + 8, 4))
    local number_of_symbols = tvb(offset + 12, 4):le_uint()
    subtree:add_le(hf.coff_number_of_symbols, tvb(offset + 12, 4))
    local opt_header_size = tvb(offset + 16, 2):le_uint()
    subtree:add_le(hf.coff_opt_header_size, tvb(offset + 16, 2))
    subtree:add_le(hf.coff_characteristics, tvb(offset + 18, 2))
    offset = offset + 20
    if opt_header_size ~= 0 then
        dissect_pe_optional_header(tvb, offset, opt_header_size, tree)
    end
    offset = offset + opt_header_size
    for i = 1, number_of_sections do
        offset = dissect_coff_section(tvb, offset, tree, machine, i, coff_start)
    end
    if symbol_table_ptr ~= coff_start and number_of_symbols ~= 0 then
        local string_table_ptr = symbol_table_ptr + 18 * number_of_symbols
        for i = 0, number_of_symbols - 1 do
            local symbol_record_offset = symbol_table_ptr + 18 * i
            dissect_coff_symbol_record(tvb, symbol_record_offset, tree, i, string_table_ptr)
        end
    end
    -- XXX this assumes that all data is covered by the sections.
    return offset + file_size
end

local function dissect_coff_archive_member(tvb, offset, file_size, tree)
    local offset_end = offset + file_size
    if tvb(offset, 4):le_uint() == 0xffff0000 then
        offset = dissect_coff_import_header(tvb, offset, file_size, tree)
    else
        offset = dissect_coff_file_header(tvb, offset, file_size, tree, offset)
    end
    if offset < offset_end then
        tree:add(hf.unprocessed, tvb(offset, offset_end - offset))
    end
end


local function get_coff_type(file_id, member_number, obj_index_adjust)
    if member_number <= 2 and file_id == "/" and not obj_index_adjust[0] then
        -- Assume COFF Linker archive format, set a sentinel value will be
        -- replaced later while processing regular archive members.
        obj_index_adjust[0] = -1
    end
    if member_number == 1 and file_id == "/" then
        -- The archive member is one of the two linker members.
        -- Both of the linker members have this name.
        return "First Linker Member", dissect_coff_first_linker_member
    elseif member_number == 2 and file_id == "/" then
        return "Second Linker Member", dissect_coff_second_linker_member
    elseif member_number <= 3 and file_id == "//" then
        -- The archive member is the longnames member, which consists of a
        -- series of null-terminated ASCII strings. The longnames member is the
        -- third archive member and must always be present even if the contents
        -- are empty.
        return "Longnames Member", dissect_coff_longnames_member
    end
    if obj_index_adjust[0] then
        if obj_index_adjust[0] == -1 then
            obj_index_adjust[0] = member_number - 1
        end
        local label = string.format("OBJ File %d", member_number - obj_index_adjust[0])
        return label, dissect_coff_archive_member
    else
        return nil, nil
    end
end

local function dissect_one(tvb, offset, pinfo, tree, member_number, symbols_map, member_names_map, obj_index_adjust)
    -- File header (based on the Wikipedia article):
    --  0   16  File identifier             ASCII
    -- 16   12  File modification timestamp Decimal
    -- 28    6  Owner ID                    Decimal
    -- 34    6  Group ID                    Decimal
    -- 40    8  File mode                   Octal
    -- 48   10  File size in bytes          Decimal
    -- 58    2  Ending characters           0x60 0x0A
    local subtree = tree:add(hf.entry, tvb(offset, 60))
    local htree = subtree:add(hf.header, tvb(offset, 60))
    local file_id = tvb:raw(offset, 16):gsub(" +$", "")
    htree:append_text(string.format(": id=%s", file_id))
    local entry_label, data_dissector = get_coff_type(file_id, member_number, obj_index_adjust)
    if entry_label then
        subtree:set_text(entry_label)
    end
    local member_name
    if string.match(file_id, "^/%d+$") then
        member_name = member_names_map[tonumber(file_id:sub(2))]
    end
    subtree:append_text(string.format(" (%s)", member_name or file_id:gsub("/$", "")))
    local sym = symbols_map[offset]
    if sym then
        local syms = table.concat(sym, ", ")
        subtree:append_text(string.format(" for %s", syms))
    end
    htree:add(hf.file_id, tvb(offset, 16))
    htree:add(hf.file_mtime, tvb(offset + 16, 12), NSTime(tonumber(tvb:raw(offset + 16, 12))))
    htree:add(hf.owner_id, tvb(offset + 28, 6))
    htree:add(hf.group_id, tvb(offset + 34, 6))
    htree:add(hf.file_mode, tvb(offset + 40, 8))
    local file_size = tonumber(tvb:raw(offset + 48, 10))
    htree:add(hf.file_size, tvb(offset + 48, 10))
    htree:append_text(string.format(" filesize=%d", file_size))
    htree:add(hf.end_chars, tvb(offset + 58, 2))
    htree:add(hf.file_data, tvb(offset + 60, file_size))
    if data_dissector == dissect_coff_first_linker_member or data_dissector == dissect_coff_second_linker_member then
        data_dissector(tvb, offset + 60, file_size, subtree, symbols_map)
    elseif data_dissector == dissect_coff_longnames_member then
        data_dissector(tvb, offset + 60, file_size, subtree, member_names_map)
    elseif data_dissector then
        data_dissector(tvb, offset + 60, file_size, subtree)
    end
    offset = offset + 60 + file_size
    local padlen = 0
    if file_size % 2 == 1 then
        htree:add(hf.padding, tvb(offset, 1))
        offset = offset + 1
    end
    subtree:set_len(60 + file_size + padlen)
    return offset
end

function proto_ar.dissector(tvb, pinfo, tree)
    -- Magic 8 bytes followed by multiple file header + data
    pinfo.cols.protocol = "ar"
    --pinfo.cols.info = ""
    tree:add(hf.magic, tvb(0, 8))
    local next_offset = 8
    local member_number = 1
    local symbols_map = {}
    local member_names_map = {}
    local obj_index_adjust = {}
    while next_offset and next_offset < tvb:len() do
        next_offset = dissect_one(tvb, next_offset, pinfo, tree, member_number, symbols_map, member_names_map, obj_index_adjust)
        member_number = member_number + 1
    end
    return next_offset
end

local function ar_heur(tvb, pinfo, tree)
    if tvb:len() < 8 or tvb:raw(0, 8) ~= "!<arch>\n" then
        return false
    end

    proto_ar.dissector(tvb, pinfo, tree)
    return true
end

function proto_pe.dissector(tvb, pinfo, tree)
    pinfo.cols.protocol = "PE"
    --pinfo.cols.info = ""

    local dos = tree:add(pe_hf.dos, tvb(0, 64))
    dos:add(pe_hf.dos_magic, tvb(0, 2))
    dos:add_le(pe_hf.dos_lfanew, tvb(60, 4))
    local lfanew = tvb(60, 4):le_uint()
    if lfanew > 64 then
        tree:add(pe_hf.dos_stub, tvb(64, lfanew - 64))
    end

    tree:add(pe_hf.magic, tvb(lfanew, 4))
    local offset = lfanew + 4
    offset = dissect_coff_file_header(tvb, offset, tvb:len() - offset, tree, 0)
    return offset
end

local function pe_heur(tvb, pinfo, tree)
    if tvb:len() < 64 or tvb:raw(0, 2) ~= "MZ" then
        return false
    end
    local lfanew = tvb(60, 4):le_uint()
    if tvb:len() < lfanew + 4 or tvb:raw(lfanew, 4) ~= "PE\0\0" then
        return false
    end

    proto_pe.dissector(tvb, pinfo, tree)
    return true
end

-- Register MIME types in case an the file appears over HTTP.
DissectorTable.get("media_type"):add("application/x-archive", proto_ar)
DissectorTable.get("media_type"):add("application/x-dosexec", proto_pe)

-- Ensure that files can directly be opened (after any FileHandler has accepted
-- it, see below).
proto_ar:register_heuristic("wtap_file", ar_heur)
proto_pe:register_heuristic("wtap_file", pe_heur)


--
-- File handler (for directly interpreting opening an ar/PE file in Wireshark)
-- Actually, all it does is recognizing the file format and passing one packet
-- to the MIME dissector.
--

local ar_fh = FileHandler.new("ar", "ar", ".LIB and .a archive and PE (exe/dll) file reader", "rms")

-- Check if file is really a ar file (return true if it is)
function ar_fh.read_open(file, cinfo)
    local buf = file:read(8)
    -- ar format?
    local ok = buf == "!<arch>\n"
    -- PE format? (64 bytes IMAGE_DOS_HEADER starting with "MZ" magic and
    -- four bytes at the end of this header pointing to the PE start).
    if not ok and buf:sub(1, 2) == "MZ" and file:seek("set", 60) then
        local peoff = Struct.unpack("<I4", file:read(4))
        ok = peoff and file:seek("set", peoff) and file:read(4) == "PE\0\0"
    end
    if not ok then
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
local function ar_fh_read(file, cinfo, finfo)
    local p = cinfo.private_table
    local curpos = file:seek("cur")

    -- Fail on EOF
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
ar_fh.read = ar_fh_read

-- Reads packet at offset (returns true on success and false on failure)
function ar_fh.seek_read(file, cinfo, finfo, offset)
    file:seek("set", offset)
    -- Return a boolean since WS < 2.4 has an undocumented "feature" where
    -- strings (including numbers) are treated as data.
    return ar_fh_read(file, cinfo, finfo) ~= false
end

-- Hints for when to invoke this dissector.
ar_fh.extensions = "lib;a;dll;exe"

register_filehandler(ar_fh)
