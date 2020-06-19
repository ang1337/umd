#pragma once
#include <memory>
#include <cstdint>
#include <fstream>
#include <string>
#include <utility>
#include <vector>
#include <thread>
#include <atomic>

class Inspector;

struct AddressRangeInfo {
    std::pair<std::uint64_t, std::uint64_t> pages_rng;
    std::string rng_permissions;
    unsigned page_cnt;
    std::uint64_t mapped_rng_start_offset,
             mapped_rng_end_offset;
};

class Dumper {
    public:
        Dumper(const pid_t);
        Dumper(const std::string&, const std::string&);
        ~Dumper();
        void dump_memory(const pid_t, const std::string&) noexcept;
        const std::vector<std::uint8_t>& get_memory_dump() const noexcept;
        const std::vector<AddressRangeInfo>& get_addr_range_info() const noexcept;
        bool is_in_range(const std::uint64_t, const std::size_t) noexcept; 
        Inspector* get_inspector_obj() const noexcept;
    private:
        /* first - the address of the first page of contiguous memory chunk in layout
         * second - the amount of pages in contiguous memory chunk */
        std::vector<std::pair<std::uint64_t, std::size_t>> contiguous_pages_blocks;
        const pid_t target_pid;
        const int page_size;
        int proc_mem_fd;
        std::ifstream proc_maps_istream,
                      dump_istream;
        std::vector<AddressRangeInfo> page_addr_ranges_info;
        std::string proc_maps_state_output;
        void accumulate_mem_dump(const std::uint64_t, const std::size_t, const std::size_t) noexcept;
        void thread_dump_memory_block(unsigned long, const unsigned long) noexcept;
        void mt_dump_memory(std::vector<std::thread>&, const unsigned long, unsigned long, unsigned long) noexcept;
        std::vector<std::uint8_t> memory;
        AddressRangeInfo extract_address_range_info(const std::string& line) noexcept;
        std::pair<std::string, std::string> dump_to_disk(const pid_t, const std::string&) noexcept;
        void get_memory_layout(bool = false) noexcept;
        Inspector* inspector;
        std::atomic<std::uint64_t> total_bytes;
};
