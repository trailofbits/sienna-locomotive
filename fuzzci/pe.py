import numpy as np
import pefile
import os

def add_jmp_section(in_path, out_path):
    pe = pefile.PE(in_path)
    print dir(pe)
    print dir(pe.DOS_HEADER)
    print dir(pe.OPTIONAL_HEADER)

    # Calculate section table's offset
    section_table_off = pe.DOS_HEADER.e_lfanew 
    section_table_off += 4 # pe signature size
    section_table_off += pe.FILE_HEADER.sizeof()
    section_table_off += pe.FILE_HEADER.SizeOfOptionalHeader

    # Check for available space in section table
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    section_count = pe.FILE_HEADER.NumberOfSections
    extra_space = size_of_headers - (section_table_off + 0x28 * section_count)
    # Count of section table entries that can fit in section table
    available_sections = extra_space / 0x28

    if available_sections == 0:
        print 'No space in header for section, add functionality!'
        return

    section_name = '.remill'

    sections = pe.sections

    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment

    last_virtual_size = sections[-1].Misc_VirtualSize
    last_virtual_address = sections[-1].VirtualAddress

    # Calculate virtual address of appended section
    virtual_address = last_virtual_address + last_virtual_size
    if last_virtual_size % section_alignment != 0:
        virtual_address += section_alignment 
        virtual_address -= last_virtual_size % section_alignment

    # Save old entry point for jmp instruction
    old_entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint

    # Set new entry point to the new
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = virtual_address

    # Calculate the jump from new section to old start
    distance = virtual_address + 5 - old_entry_point
    distance32 = np.int32(-distance)

    # Create assembly
    contents = '\xE9%s\xCC' % distance32.tobytes()

    # Calculate virtual size
    virtual_size = len(contents)

    # Pad contents to match file alignment
    if len(contents) % file_alignment != 0:
        extra = len(contents) % file_alignment
        contents += '\x00' * (file_alignment - extra)

    # Calculate raw size
    raw_size = len(contents)

    # Increase size of code and size of image to account for appended section
    pe.OPTIONAL_HEADER.SizeOfCode += raw_size
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_address + virtual_size

    # Calculate raw address of appended section
    raw_address = sections[-1].PointerToRawData + sections[-1].SizeOfRawData

    # Add in the data (there shouldn't be any after it)
    pe.__data__ = pe.__data__[:raw_address] + contents + pe.__data__[raw_address:]

    # Get file offset of new section table entry
    section_count = pe.FILE_HEADER.NumberOfSections
    section_header_off = section_table_off + 0x28 * section_count

    # Write data
    pe.set_bytes_at_offset(section_header_off, section_name)
    pe.set_dword_at_offset(section_header_off + 0x08, virtual_size)
    pe.set_dword_at_offset(section_header_off + 0x0C, virtual_address)
    pe.set_dword_at_offset(section_header_off + 0x10, raw_size)
    pe.set_dword_at_offset(section_header_off + 0x14, raw_address)
    pe.set_dword_at_offset(section_header_off + 0x18, 0x0) # relocations address
    pe.set_dword_at_offset(section_header_off + 0x1C, 0x0) # line numbers address
    pe.set_word_at_offset(section_header_off + 0x20, 0x0) # relocations count
    pe.set_word_at_offset(section_header_off + 0x22, 0x0) # line numbers count
    pe.set_dword_at_offset(section_header_off + 0x24, 0x60000020) # characteristics

    # Increment the number of sections
    pe.FILE_HEADER.NumberOfSections = section_count + 1

    # Write the file
    pe.write(filename=out_path)
    pe.close()

if __name__ == '__main__':
    in_path = '../SiennaWin/debug/SiennaWin.exe'
    out_path = '../SiennaWin/debug/SiennaMod.exe'
    add_jmp_section(in_path, out_path)