#include "../include/Inspector.h"
#include <elf.h>
#include <cstring>
#include <iostream>

/* 18 is the offset inside the ELF executable header that holds 2 byte value that defines the machine type of the target binary (32 or 64 bit) */
Inspector::Inspector(std::vector<AddressRangeInfo> &proc_maps_info) 
    : proc_maps_info(proc_maps_info), machine_type_ehdr_offset(18) {}

/* maps virtual addresses to memory dump vector offsets */
void Inspector::map_address_space() noexcept {
    auto proc_maps_iter { proc_maps_info.begin() };
    proc_maps_iter->mapped_rng_start_offset = 0;
    auto curr_offset { proc_maps_iter->pages_rng.second - proc_maps_iter->pages_rng.first };
    proc_maps_iter->mapped_rng_end_offset = curr_offset;
    proc_maps_iter++;
    for ( ; proc_maps_iter != proc_maps_info.end(); proc_maps_iter++) {
        proc_maps_iter->mapped_rng_start_offset = curr_offset;
        curr_offset += (proc_maps_iter->pages_rng.second - proc_maps_iter->pages_rng.first);
        proc_maps_iter->mapped_rng_end_offset =  curr_offset;
    }
}

/* returns an appropriate offset inside the memory dump buffer according to the provided valid virtual address */
std::uint64_t Inspector::get_offset(const std::uint64_t address) const noexcept {
    ssize_t low_idx {}, high_idx { static_cast<ssize_t>(proc_maps_info.size() - 1) };
    while (low_idx <= high_idx) {
        auto mid { (low_idx + ((high_idx - low_idx) / 2))  };
        auto curr_proc_maps_entry { proc_maps_info.at(mid) };
        if ( (curr_proc_maps_entry.pages_rng.first <= address) 
              &&
             (curr_proc_maps_entry.pages_rng.second > address) ) {
            
            return curr_proc_maps_entry.mapped_rng_start_offset + (address - curr_proc_maps_entry.pages_rng.first);
        
        } else if (address >= curr_proc_maps_entry.pages_rng.second) {
            low_idx = mid + 1;
        } else {
            high_idx = mid - 1;
        }
    }
    return 0; // technically unreachable
}

/* extracts a memory chunk from the dump */
std::vector<std::uint8_t> Inspector::read_memory(const std::vector<std::uint8_t>& memory, 
                                                 const std::uint64_t offset, 
                                                 const std::uint64_t size) const noexcept { 
    std::vector<std::uint8_t> read_memory_chunk { memory.begin() + offset, 
                                                  memory.begin() + offset + size };
    return read_memory_chunk;
}

std::uint16_t Inspector::check_machine_type(const std::vector<std::uint8_t> &memory_dump) const noexcept {
    std::uint16_t ptr_size {};
    /* check if the offset is reachable in order to avoid invalid memory access */
    if (memory_dump.size() > machine_type_ehdr_offset) {
        std::memcpy(&ptr_size, &memory_dump.at(machine_type_ehdr_offset), sizeof(std::uint16_t));
    } else {
        std::cerr << "The ELF header seems to be broken, the machine type info is not available" << std::endl;
        return sizeof(std::uint64_t);
    }
    // not super robust, for now it works only with x86/x86-64 binaries
    if (ptr_size == EM_386) {
        ptr_size = sizeof(std::uint32_t);
    } else {
        ptr_size = sizeof(std::uint64_t);
    }
    return ptr_size;
}
