#include "../inc/Dumper.hpp"
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <iostream>
#include <thread>
#include <sys/ptrace.h>
#include <chrono>
#include <algorithm>
#include "../inc/umd_exception.hpp"

// API user can print out the memory metadata map in a nice readable format via cout
std::ostream& operator << (std::ostream &os, const umd::memory_metadata_map &mem_map) {
    unsigned mem_region_cnt {};
    auto print_mem_flags = [](std::ostream &os, const umd::MemoryRegion &curr_mem_region) {
        for (const auto flag : curr_mem_region.flags) {
            os << flag;
        }
        os << '\n';
    };
    for (const auto &curr_mem_region : mem_map) {
        os << curr_mem_region.first.get_seq_num() << ") Memory region name: " << curr_mem_region.first.get_name() << '\n'
           << "Total memory size: " << curr_mem_region.second.second.size() << '\n';
        for (const auto &mem_rng : curr_mem_region.second.first) {
            os << "Start address: 0x" << std::hex << mem_rng.start_address
                << " | End address : 0x" << mem_rng.end_address
                << " | File offset: 0x" << mem_rng.file_offset << std::dec
                << " | Flags: ";
            print_mem_flags(os, mem_rng);
        }
        os << '\n';
    }
    return os;
}

namespace umd {
    // umd ctor
    // @ target_pid - target PID to dump
    Dumper::Dumper(const pid_t target_pid) : _target_pid(target_pid) {
        procmem_fd = open(("/proc/" + std::to_string(_target_pid) + "/mem").data(), O_RDWR);
        if (procmem_fd == -1) {
            throw umd_exception("Cannot open /proc/" + std::to_string(_target_pid) + "/mem, try to use umd with root privileges");
        }
        procmaps_ifs.open("/proc/" + std::to_string(_target_pid) + "/maps");
        if (!procmaps_ifs.is_open()) {
            close(procmem_fd);
            throw umd_exception("Cannot open /proc/" + std::to_string(_target_pid) + "/maps");
        }
    }
    // umd dtor
    Dumper::~Dumper() {
        close(procmem_fd);
        procmaps_ifs.close();
        ptrace(PTRACE_DETACH, _target_pid, nullptr, nullptr);
    }

    // parses /proc/PID/maps of the target process
    // return value - parsed memory metadata map that contains the relevant information about target process' memory space
    memory_metadata_map Dumper::parse_procmaps() {
        // Ensure that procmaps file stream begins at offset 0
        procmaps_ifs.seekg(0, std::ios::beg); 
        std::string curr_line {};
        enum : unsigned {
            PROCMAPS_ADDR_RNG_IDX,
            PROCMAPS_FLAGS,
            PROCMAPS_FILE_OFFSET_IDX,
            PROCMAPS_NAME_IDX = 5
        };
        std::vector<MemoryRegion> mem_vec {};
        memory_metadata_map mem_map {};
        unsigned mem_seq_num {};
        // read all lines from /proc/PID/maps
        while (std::getline(procmaps_ifs, curr_line)) {
            std::string curr_token {};
            std::stringstream ss(curr_line); 
            unsigned procmaps_line_idx {};
            MemoryRegion curr_mem_region {};
            while (std::getline(ss, curr_token, ' ')) {
                // skip empty spaces in the currently parsed line
                if (curr_token.size()) {
                    switch (procmaps_line_idx) {
                        // address range needs to be parsed
                        case PROCMAPS_ADDR_RNG_IDX: {
                            auto hyphen_idx { curr_token.find('-') };
                            curr_mem_region.start_address = std::stoul(curr_token.substr(0, hyphen_idx), nullptr, 16);
                            curr_mem_region.end_address = std::stoul(curr_token.substr(hyphen_idx + 1), nullptr, 16);
                        }
                            break;
                        case PROCMAPS_FLAGS:
                            std::copy(curr_token.cbegin(), curr_token.cend(), curr_mem_region.flags.begin());
                            break;
                        case PROCMAPS_FILE_OFFSET_IDX:
                            curr_mem_region.file_offset = std::stoul(curr_token, nullptr, 16);
                            break;
                        case PROCMAPS_NAME_IDX:
                            curr_mem_region.name = curr_token;
                            break;
                        default:
                            break;
                    }
                    procmaps_line_idx++;
                }
            }
            if (!curr_mem_region.name.size()) {
                curr_mem_region.name = "[ANONYMOUS]";
            }
            mem_vec.push_back(std::move(curr_mem_region));
        }
        unsigned step {};
        for (auto outer_iter { mem_vec.cbegin() }; outer_iter < mem_vec.cend(); outer_iter += step) {
            step = 0;
            for (auto inner_iter { outer_iter }; inner_iter != mem_vec.cend() && inner_iter->name == outer_iter->name; ++inner_iter) {
                step++;
            }
            std::vector<MemoryRegion> cont_mem_vec(outer_iter, outer_iter + step);
            auto cont_mem_size { (cont_mem_vec.cend() - 1)->end_address - cont_mem_vec.cbegin()->start_address };
            mem_map[ MemoryMetadataKey(outer_iter->name, ++mem_seq_num) ] = { std::move(cont_mem_vec), std::vector<std::uint8_t>(cont_mem_size) };
        }
        return mem_map;
    }

    // dump worker thread
    // @group - vector of iterators related to the same group of contiguous memory regions
    void Dumper::dump_worker(const std::vector<memory_metadata_map::iterator> &group) {
        for (auto &entry : group) {
            auto curr_mem_start_addr { entry->second.first.begin()->start_address };
            auto curr_mem_end_addr { (entry->second.first.end() - 1)->end_address };
            auto cont_mem_size { curr_mem_end_addr - curr_mem_start_addr };
            auto &curr_cont_mem_content { entry->second.second };
            pread(procmem_fd, &curr_cont_mem_content.at(0), cont_mem_size, curr_mem_start_addr);
        }
    }

    // groups up contiguous memory regions according to the amount of threads for faster in-memory dumping process
    // @ mem_map - memory metadata map that contains all the information about the target process memory space
    // @ dump_thread_cnt - the amount of threads allocated for dumping routine 
    // @ regions_per_thread - how many regions will be dumped via 1 dump worker thread
    // @ return value - vector of vector of memory metadata map iterators, each outer vector cell represents a separate contiguous memory region group for further dump
    const std::vector<std::vector<memory_metadata_map::iterator>> Dumper::group_mem_regions(memory_metadata_map &mem_map, 
                                                                                            const unsigned dump_thread_cnt,
                                                                                            const unsigned regions_per_thread) {
        std::vector<std::vector<memory_metadata_map::iterator>> grouped_mem_regions_vec {};
        auto outer_map_iter { mem_map.begin() };
        for (unsigned outer_cnt {}; outer_cnt < dump_thread_cnt; ++outer_cnt) {
            std::vector<memory_metadata_map::iterator> mem_iter_vec {};
            for (unsigned cnt {}; cnt < regions_per_thread; ++cnt) {
                mem_iter_vec.push_back(outer_map_iter++);
            }
            grouped_mem_regions_vec.push_back(std::move(mem_iter_vec));
        }
        // check if remainder groups exist
        if (mem_map.size() % dump_thread_cnt) {
            std::vector<memory_metadata_map::iterator> mem_iter_vec {};
            while (outer_map_iter != mem_map.end()) {
                mem_iter_vec.push_back(outer_map_iter++);
            }
            grouped_mem_regions_vec.push_back(std::move(mem_iter_vec));
        }
        return grouped_mem_regions_vec;
    }

    // dump an in-memory dump to disk
    // @ mem_map - memory metadata map that contains all the information about the target process memory space
    // @ dump_path - absolute path for a dump file
    void Dumper::dump_to_disk(const memory_metadata_map &mem_map, const std::string &dump_path) {
        std::ofstream dump_ofs(dump_path, std::ios::binary);
        if (!dump_ofs.is_open()) {
            throw umd_exception("Cannot open the file path -> " + dump_path + " for memory dump");
        }
        auto start { std::chrono::high_resolution_clock::now() };
        unsigned long total_memory {};
        for (const auto &mem : mem_map) {
            dump_ofs.write(reinterpret_cast<const char*>(&mem.second.second.at(0)), mem.second.second.size());
            total_memory += (mem.second.second.size());
        }
        auto end { std::chrono::high_resolution_clock::now() };
        auto time_elapsed { std::chrono::duration_cast<std::chrono::milliseconds>(end - start) };
        std::cout << "Dumped " << total_memory << " bytes to disk -> [" << dump_path << "] in " << static_cast<double>(time_elapsed.count()) / 1000 << " seconds\n";
        dump_ofs.close();
    }
    
    // dumps the whole target process memory into the memory metadata map exposed in API
    // return value - memory metadata map contains all the relevant data of a target process which memory has been dumped
    const memory_metadata_map Dumper::dump_memory() {
        // first of all attach to the target process
        if (ptrace(PTRACE_ATTACH, _target_pid, nullptr, nullptr) == -1) {
            throw umd_exception("Cannot attach to PID #" + std::to_string(_target_pid));
        }
        auto parsed_mem_data_map { parse_procmaps() };
        std::cout << "Metadata map size: " << parsed_mem_data_map.size() << std::endl;
        unsigned long total_memory {};
        for (const auto &x : parsed_mem_data_map) {
            total_memory += (x.second.second.size());
        }
        // use the half of available logical cores for memory dumping routine
        auto dump_threads_cnt { std::thread::hardware_concurrency() / 2 };
        unsigned long map_entries_per_thread { parsed_mem_data_map.size() / dump_threads_cnt };
        const auto grouped_mem_map_iter_vec { group_mem_regions(parsed_mem_data_map, dump_threads_cnt, map_entries_per_thread) };
        std::vector<std::thread> thread_pool {};
        auto timestamp_start { std::chrono::high_resolution_clock::now() };
        // fire up the thread pool for faster in-memory dump
        for (auto &group : grouped_mem_map_iter_vec) {
            thread_pool.push_back(std::thread(&Dumper::dump_worker, this, group));
        }
        for (auto &curr_thread : thread_pool) {
            if (curr_thread.joinable()) {
                curr_thread.join();
            }
        }
        auto timestamp_end { std::chrono::high_resolution_clock::now() };
        auto time_elapsed { std::chrono::duration_cast<std::chrono::milliseconds>(timestamp_end - timestamp_start) };
        std::cout << "Dumped " << total_memory << " bytes in-memory in " << static_cast<double>(time_elapsed.count()) / 1000 << " seconds\n";
        ptrace(PTRACE_DETACH, _target_pid, nullptr, nullptr);
        // detach from target process
        return parsed_mem_data_map;
    }

    // inspects the dumped memory
    // @ mem_metadata_map - memory metadata map that contains all the information about the target process memory space
    // @ address - virtual memory address to read memory from
    // @ size - the size of an inspected memory chunk
    // return value - an optional byte vector, use has_value() method to check if the memory content has been read at a given vaddr
    std::optional<byte_vector> Dumper::inspect_memory(const memory_metadata_map& mem_metadata_map, 
                                                                    const unsigned long address, 
                                                                    const unsigned long size) const {
        for (const auto &mem_data : mem_metadata_map) {
            auto curr_mem_data_start_iter { mem_data.second.first.cbegin() };
            auto curr_mem_data_end_iter { mem_data.second.first.cend() - 1 };
            // check if the requested memory chunk resides in existing memory dump boundaries
            if (curr_mem_data_start_iter->start_address <= address && 
                curr_mem_data_end_iter->end_address > address &&
                (address + size) < curr_mem_data_end_iter->end_address) {
                const unsigned long inrange_offset { address - curr_mem_data_start_iter->start_address };
                byte_vector mem_chunk(mem_data.second.second.cbegin() + inrange_offset, 
                                      mem_data.second.second.cbegin() + inrange_offset + size);
                return mem_chunk; 
            }
        }
        return {};
    }
}