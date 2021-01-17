#pragma once 
#include <fstream>
#include <bitset>
#include <string>
#include <cstdint>
#include <vector>
#include <map>
#include <optional>
#include <utility>
#include <array>
#include "umd_exception.hpp"

namespace umd {
    struct MemoryRegion {
        std::array<char, 5> flags;
        std::string name; 
        unsigned long start_address;
        unsigned long end_address;
        unsigned long file_offset;
    };
    struct MemoryMetadataKey {
        private:
        std::string _name;
        unsigned _sequence_number;
        public:
        const unsigned get_seq_num() const {
            return _sequence_number;
        }
        const std::string& get_name() const {
            return _name;
        }
        MemoryMetadataKey(const std::string &name, const unsigned seq_num) : _name(name), _sequence_number(seq_num) {} 
        MemoryMetadataKey(const unsigned seq_num) : _sequence_number(seq_num) {}
        inline bool operator < (const MemoryMetadataKey &rhs) const {
            return this->_sequence_number < rhs._sequence_number;
        }
    };
    using memory_region_data_vec = std::vector<MemoryRegion>;
    using byte_vector = std::vector<std::uint8_t>;
    using memory_metadata_map = std::map<MemoryMetadataKey, std::pair<memory_region_data_vec, byte_vector>>;
    class Dumper {
        private:
            std::ifstream procmaps_ifs;
            int procmem_fd;
            const pid_t _target_pid;
            memory_metadata_map parse_procmaps();
            void dump_worker(const std::vector<memory_metadata_map::iterator> &group);
            const std::vector<std::vector<memory_metadata_map::iterator>> group_mem_regions(memory_metadata_map &mem_map, const unsigned dump_thread_cnt, const unsigned regions_per_thread);
        public:
            Dumper(const pid_t target_pid);
            ~Dumper();
            Dumper(const Dumper&) = delete;
            Dumper& operator = (const Dumper&) = delete;
            Dumper& operator = (Dumper&&) noexcept = default;
            Dumper(Dumper&&) noexcept = default;
            const memory_metadata_map dump_memory();
            void dump_to_disk(const memory_metadata_map &mem_map, const std::string &dump_path);
            std::optional<byte_vector> inspect_memory(const memory_metadata_map& mem_metadata_map, const unsigned long address, const unsigned long size) const;
    };
}

std::ostream& operator << (std::ostream &os, const umd::memory_metadata_map &mem_map);