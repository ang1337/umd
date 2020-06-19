#include "../include/Dumper.h"
#include "../include/Inspector.h"
#include "../include/Validator.h"
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <sched.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sstream>
#include <sys/wait.h>
#include <unistd.h>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <sys/resource.h>

using namespace std::chrono;

/* this constructor is called in attach mode */
Dumper::Dumper(const pid_t pid) : target_pid(pid), 
                                  page_size(getpagesize()), 
                                  total_bytes(0),
                                  proc_mem_fd(0),
                                  inspector(nullptr) { // constructor
    /* open all the required procfs entries */
    std::string procfs_maps_path { "/proc/" + std::to_string(target_pid) + "/maps" },
                procfs_mem_path { "/proc/" + std::to_string(target_pid) + "/mem" };
    proc_maps_istream.open(procfs_maps_path.c_str());
    /* /proc/pid/mem doesn't work well with C++ I/O streams, so C-like file I/O is the option */
    proc_mem_fd = open(procfs_mem_path.c_str(), O_RDWR);
    /* procfs file opening error handling */
    if (!proc_maps_istream || (proc_mem_fd < 3)) {
        if (!proc_maps_istream && (proc_mem_fd > 2)){
            std::cerr << procfs_maps_path << " opening failure" << std::endl;
            close(proc_mem_fd);
        } else if (proc_maps_istream && (proc_mem_fd < 3)) {
            std::cerr << procfs_mem_path << " opening failure" 
                      << "\nTry to run the umd as root" << std::endl;
            proc_maps_istream.close();
        } else {
            std::cerr << procfs_maps_path << " and" << procfs_mem_path << " opening failure" << std::endl;
        }
        ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
        exit(EXIT_FAILURE);
    }
    get_memory_layout();
}

/* this constructor is called in inspect mode */
Dumper::Dumper(const std::string &path_to_memory_layout, const std::string &path_to_dump) 
    : page_size(getpagesize()), proc_mem_fd(0), inspector(nullptr), target_pid(0) {
    
    proc_maps_istream.open(path_to_memory_layout);
    dump_istream.open(path_to_dump);
    if (!proc_maps_istream || !dump_istream) {
        std::cerr << "ERROR : procfs file opening failure\n" << std::endl;
        exit(EXIT_FAILURE);
    }
    /* Lower nice number is set for performance reasons */
    setpriority(PRIO_PROCESS, getpid(), -20);
    get_memory_layout(true);
    std::cout << "Loading the " << path_to_dump << " from the disk to the buffer..." 
              << "\nMemory dump size : " << memory.size() << " bytes"
              << std::fixed << std::setprecision(2) 
              << " / " << static_cast<float>(memory.size()) / 1000.f << " kilobytes"
              << " / " << std::setprecision(4) << static_cast<float>(memory.size()) / 1000000.f << " megabytes"
              << " / " << std::setprecision(6) << static_cast<float>(memory.size()) / 1000000000.f << " gigabytes" 
              << std::endl;
    auto start { high_resolution_clock::now() };
    dump_istream.read(reinterpret_cast<char*>(memory.data()), memory.size());
    auto stop { high_resolution_clock::now() };
    auto time_elapsed { duration_cast<duration<double>>(stop - start) };
    std::cout << "Time elapsed : " << time_elapsed.count() 
              << " seconds (loading memory dump from the disk to the buffer)" << std::endl;
    /* Reset the nice number back to default */
    setpriority(PRIO_PROCESS, getpid(), 0);
}

Dumper::~Dumper() { 
    if (proc_maps_istream) {
        proc_maps_istream.close();
    }
    if (dump_istream) {
        dump_istream.close();
    }
    if (proc_mem_fd) {
        close(proc_mem_fd);
    }
    if (inspector) {
        delete inspector;
        inspector = nullptr;
    }
}
 
const std::vector<std::uint8_t>& Dumper::get_memory_dump() const noexcept {
    return memory;
}

const std::vector<AddressRangeInfo>& Dumper::get_addr_range_info() const noexcept {
    return page_addr_ranges_info;
}

/* this method parses virtual pages range metadata of a single line from /proc/pid/maps */
AddressRangeInfo Dumper::extract_address_range_info(const std::string& line) noexcept { 
    std::string start_addr {}, 
                end_adrr {},
                rng_permissions {},
                token {};
    std::istringstream line_sstream(line);
    std::getline(line_sstream, token, ' '); // get addr range
    auto hyphen_idx { token.find("-") };
    start_addr = token.substr(0, hyphen_idx); // extract the start address
    end_adrr = token.substr(hyphen_idx + 1); // extract the end address
    std::getline(line_sstream, rng_permissions, ' '); // get permissions
    std::pair<std::uint64_t, std::uint64_t> curr_addr_range { std::stoull(start_addr, nullptr, 16),
                                                    std::stoull(end_adrr, nullptr, 16) };
    auto page_amount { (curr_addr_range.second - curr_addr_range.first) / page_size };
    return { {curr_addr_range},
             {rng_permissions},
             static_cast<unsigned>(page_amount),
             0,
             0 };
}

Inspector* Dumper::get_inspector_obj() const noexcept {
    return inspector;
}

/* this method checks if the current number of bytes can be read from the current address
 * famous integer overflow bug in binary search is handled */
bool Dumper::is_in_range(const std::uint64_t address, const std::size_t code_size) noexcept {
    ssize_t low_idx {}, high_idx { static_cast<ssize_t>(page_addr_ranges_info.size() - 1) };
    while (low_idx <= high_idx) { 
        auto mid_idx { (low_idx + ((high_idx - low_idx) / 2))  };
        auto curr_page_addr_rng_entry { page_addr_ranges_info.at(mid_idx) };
        if ( (curr_page_addr_rng_entry.pages_rng.first <= address) && 
             
             (curr_page_addr_rng_entry.pages_rng.second > address) &&
             
             ((address + code_size) <= curr_page_addr_rng_entry.pages_rng.second) ) {
            
                return true;

        } else if (address >= curr_page_addr_rng_entry.pages_rng.second) {
            low_idx = mid_idx + 1;
        } else {
            high_idx = mid_idx - 1;
        }
    }
    return false;
}
/* this method reads the entire /proc/pid/maps interface and fills the AddressRangeInfo vector */
void Dumper::get_memory_layout(bool inspect_mode) noexcept {
    std::string line {};
        /* get the first line */
    std::getline(proc_maps_istream, line);
    /* gets the virtual page range metadata */
    auto curr_addr_range_info { extract_address_range_info(line) };
    page_addr_ranges_info.push_back(curr_addr_range_info);
    std::size_t page_count { curr_addr_range_info.page_cnt },
                cont_page_cnt { page_count };
    /* there is no need to accumulate /proc/pid/maps output in inspect mode */
    if (!inspect_mode) {  
        proc_maps_state_output += (line + "\n");
    }
    /* push the contiguous memory block info into the vector */
    contiguous_pages_blocks.push_back({ curr_addr_range_info.pages_rng.first, curr_addr_range_info.page_cnt });
    /* do the same steps for the rest of the file based on the previous and the current line */
    while (std::getline(proc_maps_istream, line)) {
        auto curr_addr_range_info { extract_address_range_info(line) };
        if (!inspect_mode) {  
            proc_maps_state_output += (line + "\n");
        }
        page_count += curr_addr_range_info.page_cnt;
        auto prev_addr_rng { page_addr_ranges_info.back().pages_rng };
        page_addr_ranges_info.push_back(curr_addr_range_info);
        /* detect contiguous memory in the layout */
        if (prev_addr_rng.second == page_addr_ranges_info.back().pages_rng.first) {
            contiguous_pages_blocks.back().second += curr_addr_range_info.page_cnt;
        } else {
            contiguous_pages_blocks.push_back({ curr_addr_range_info.pages_rng.first, curr_addr_range_info.page_cnt });
        }
    }
    /* inspector object will be destroyed in class Dumper destructor */
    if (!inspector) {
        inspector = new Inspector(page_addr_ranges_info);
    }
    /* maps the virtual addresses to vector offsets */
    inspector->map_address_space();
    std::cout << "Contiguous memory regions: " << std::endl;
    for (const auto &cont_mem_block : contiguous_pages_blocks) {
        std::cout << "Start address: " << std::hex << cont_mem_block.first << std::dec 
                  << " | pages : " << cont_mem_block.second << std::endl;
    }
    /* resize the memory dump buffer for better performance */
    memory.resize(page_count * page_size);
}

/* this method adds contiguous memory block to the total memory dump */
inline void Dumper::accumulate_mem_dump(const std::uint64_t address, 
                                        const std::size_t bytes_to_read, 
                                        const std::size_t total_bytes_dumped_so_far) noexcept {
    lseek(proc_mem_fd, address, SEEK_SET);
    read(proc_mem_fd, &memory.at(total_bytes_dumped_so_far), bytes_to_read);
}

/* this method is called by threads, each thread dumps a separate memory blocks range to particular offset range in memory dump vector */
void Dumper::thread_dump_memory_block(unsigned long dump_from_this_idx, 
                                      const unsigned long thread_dump_range) noexcept {
    auto curr_cont_pages_block { contiguous_pages_blocks.at(dump_from_this_idx) };
    while (dump_from_this_idx < thread_dump_range) {
        accumulate_mem_dump(curr_cont_pages_block.first, 
                            curr_cont_pages_block.second * page_size, 
                            inspector->get_offset(curr_cont_pages_block.first));
        /* total_bytes is an atomic variable in order to avoid race condition */
        total_bytes += curr_cont_pages_block.second * page_size; 
        dump_from_this_idx++;
    }
}

std::pair<std::string, std::string> Dumper::dump_to_disk(const pid_t target_pid, const std::string &dump_dir) noexcept {
    using sys_clock = std::chrono::system_clock;
    std::time_t curr_sys_clock { sys_clock::to_time_t(sys_clock::now()) };
    std::string curr_time { std::ctime(&curr_sys_clock) },
                file_name { std::to_string(target_pid) };
    curr_time.resize(curr_time.size() - 1);
    std::string dump_output_file_name { file_name + ".dump." + curr_time },
                proc_maps_output_file_name { file_name + ".memory_layout." + curr_time };
    std::ofstream dump_ostream {dump_dir + "/" + dump_output_file_name, std::ios::binary },
                  proc_maps_ostream { dump_dir + "/" + proc_maps_output_file_name }; 
    if (!dump_ostream || !proc_maps_ostream) {
        std::cerr << "ERROR : Output fstream opening failure while dumping to the disk" << std::endl;
        close(proc_mem_fd);
        proc_maps_istream.close();
        ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
        exit(EXIT_FAILURE);
    }
    std::cout << "Saving the dump to the disk..." << std::endl;
    auto start { high_resolution_clock::now() };
    dump_ostream.write(reinterpret_cast<const char*>(memory.data()), memory.size());
    auto stop { high_resolution_clock::now() };
    auto time_elapsed { duration_cast<duration<double>>(stop - start) };
    std::cout << "Time elapsed : " << time_elapsed.count() << " seconds (dumping memory from the buffer to the disk)" << std::endl;
    std::cout << "Saving the /proc/" << target_pid << "/maps output..." << std::endl;
    proc_maps_ostream << proc_maps_state_output;
    dump_ostream.close();
    proc_maps_ostream.close();
    return { dump_output_file_name, proc_maps_output_file_name };
}

/* this method fetches dumping threads from a thread pool and executes them */
void Dumper::mt_dump_memory(std::vector<std::thread> &dump_threads, 
                            const unsigned long cells_per_thread, 
                            unsigned long dump_from_idx, 
                            unsigned long dump_to_idx) noexcept {
    auto thread_cnt { dump_threads.size() };
    for (std::size_t i {}; i < thread_cnt; i++) {
        dump_threads.push_back(std::thread(&Dumper::thread_dump_memory_block, this, dump_from_idx, dump_to_idx));
        dump_from_idx += cells_per_thread;
        dump_to_idx += cells_per_thread;
    }
    /* wait for all threads */
    for (auto &dump_thread : dump_threads) {
        if (dump_thread.joinable()) {
            dump_thread.join();
        }
    }
}

void Dumper::dump_memory(const pid_t target_pid, const std::string &dump_dir) noexcept { 
    /* takes an optimal amount of threads for a current hardware */
    auto thread_cnt { std::thread::hardware_concurrency() <= contiguous_pages_blocks.size() ? std::thread::hardware_concurrency() :
                                                                                                 contiguous_pages_blocks.size() };
    std::vector<std::thread> dump_threads(thread_cnt);
    unsigned long cells_per_thread { contiguous_pages_blocks.size() / thread_cnt },
                  dump_from_idx {},
                  dump_to_idx { cells_per_thread };
    std::cout << "Threads created for memory dumping : " << thread_cnt << std::endl;
    /* sets to lowest nice number for a dumping phase for performance reasons */
    setpriority(PRIO_PROCESS, getpid(), -20);
    auto start { high_resolution_clock::now() };
    mt_dump_memory(dump_threads, cells_per_thread, dump_from_idx, dump_to_idx);
    /* handles the situation when the amount of contiguous memory blocks is not divisible by the amount of threads */
    auto dump_remainder { contiguous_pages_blocks.size() % thread_cnt };
    if (dump_remainder) {
        thread_cnt = dump_remainder;
        cells_per_thread = 1;
        dump_from_idx = contiguous_pages_blocks.size() - dump_remainder;
        dump_to_idx = dump_from_idx + 1;
        dump_threads.clear();
        dump_threads.resize(thread_cnt);
        mt_dump_memory(dump_threads, cells_per_thread, dump_from_idx, dump_to_idx);
    }
    auto stop { high_resolution_clock::now() };
    auto time_elapsed { duration_cast<duration<double>>(stop - start) };
    std::cout << "Time elapsed : " << time_elapsed.count() 
              << " seconds (dumping memory from /proc/pid/mem to the buffer)" << std::endl;
    std::cout << "Total dumped memory : " << total_bytes << " bytes" 
              << std::fixed << std::setprecision(2) 
              << " / " << static_cast<float>(total_bytes ) / 1000.f << " kilobytes"
              << " / " << std::setprecision(4) << static_cast<float>(total_bytes) / 1000000.f << " megabytes"
              << " / " << std::setprecision(6) << static_cast<float>(total_bytes) / 1000000000.f << " gigabytes" 
              << std::endl;
    auto output_files { dump_to_disk(target_pid, dump_dir) };
    /* reset the nice number back to the default */
    setpriority(PRIO_PROCESS, getpid(), 0);
    std::cout << "The process memory has been successfully saved in " << dump_dir 
              << "\nCheck '" << output_files.first 
              << "' and the corresponding '" << output_files.second 
              << "' that contains /proc/pid/maps of the dumped process" << std::endl;
}
