#include "../include/dumper.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstdint>
#include <csignal>
#include <fstream>
#include <filesystem>
#include <thread>

namespace umd {

    // Dumper class constructor
    // Argument: umd mode (either attach or inspect)
    Dumper::Dumper(const umdMode umd_mode) 
      : umd_mode(umd_mode),
        intel_arch_bp_opcode(0xcc),
        dump_size(0),
        target_pid(0),
        inspector_obj(nullptr) {}

    // Dumper class destructor
    Dumper::~Dumper() {
        if (inspector_obj) {
            delete inspector_obj;
            inspector_obj = nullptr;
        }
    }
    // DumpInspector nested class constructor 
    // Arguments: 1) Path to raw binary process dump
    //            2) Path to the json metadata file to be parsed
    Dumper::DumpInspector::DumpInspector(const std::string &dump_path, const std::string &json_path) {
        // 2) load json & raw dump
        std::ifstream json_ifstream { json_path },
                      dump_ifstream { dump_path, std::ios::binary };
        if (!dump_ifstream.is_open()) {
            fprintf(stderr, "%s cannot be opened\n", dump_path.data());
            exit(EXIT_FAILURE);
        } else if (!json_ifstream.is_open()) {
            fprintf(stderr, "%s cannot be opened\n", json_path.data());
            exit(EXIT_FAILURE);
        }
        // load the json file
        json_ifstream >> loaded_json;
        // adapt the dump buffer for the full dump size
        dump_ifstream.seekg(0, std::ios::end);
        auto full_dump_size { dump_ifstream.tellg() };
        dump_ifstream.seekg(0, std::ios::beg);
        dump_buffer.resize(full_dump_size);
        // read the whole dump from the disk
        dump_ifstream.read(reinterpret_cast<char *>(&dump_buffer[0]), full_dump_size);
        json_ifstream.close();
        dump_ifstream.close();
        // generate memory map vector with all memory metadata info
        generate_mem_vec_from_json();
        // extract the dumped registers (for further optional external usage) 
        extract_dumped_regs();
    }

    // Extracts the regs dump appendix
    void Dumper::DumpInspector::extract_dumped_regs() {
        auto raw_dump_size { std::get<TUPLE_RAW_SIZE_IDX>(parsed_json_data) };
        auto dump_size_with_regs_appendix { std::get<TUPLE_SIZE_WITH_REGS_IDX>(parsed_json_data) };
        // extract the subvector from the dump which containts a register dump appendix
        const std::vector<uint8_t> regs_dump_appendix(dump_buffer.cbegin() + raw_dump_size, 
                                                      dump_buffer.cbegin() + dump_size_with_regs_appendix);
        std::memcpy(&dumped_regs, &regs_dump_appendix[0], sizeof(struct user_regs_struct));
    }

    void Dumper::get_dumped_regs(struct user_regs_struct &regs) const {
        if (umd_mode == umdMode::INSPECT_MODE) {
            if (inspector_obj) {
                regs = inspector_obj->dumped_regs;
            } else {
                std::cerr << "The dump is not inspected, call inspect_dump() method before get_dumped_regs()" << std::endl;
            }
        } else {
            std::cerr << "umd is not in inspect mode" << std::endl;
        }
    }

    // Main inspection prompt loop
    void Dumper::DumpInspector::dump_inspection_mainloop() const {
        const auto &mem_map_vec { std::get<TUPLE_MEM_MAP_IDX>(parsed_json_data) };
        std::cout << "Press Ctrl+C to break from the inspection loop" << std::endl;
        for (;;) {
            std::string address_str {};
            unsigned long bytes_to_read {};
            process_input<std::string>(address_str, "Enter the address to read from: ");
            unsigned long address { std::stoul(address_str, nullptr, 16) };
            process_input<unsigned long>(bytes_to_read, "How much bytes to read? ");
            // check if the given dump memory read attempt is valid (accidental OOB read prevention)
            auto mem_vec_node { valid_mem_access(mem_map_vec, address, bytes_to_read) };
            if (mem_vec_node != mem_map_vec.cend()) {
                // fetch the offset in the dump buffer
                const unsigned long curr_offset { mem_vec_node->buffer_offset + (address - mem_vec_node->mem_rng.first) };
                const std::vector<uint8_t> &curr_dump_buff_subvec { dump_buffer.cbegin() + curr_offset, 
                                                                    dump_buffer.cbegin() + curr_offset + bytes_to_read };
                printf("%lu bytes beginning at address %p:\n", bytes_to_read, (void *)address);
                // print the given subvector from the dump, the output width equals to pointer size
                for (unsigned long curr_byte_idx {}; curr_byte_idx < curr_dump_buff_subvec.size(); ++curr_byte_idx) {
                    if (!(curr_byte_idx % sizeof(void *))) {
                        printf("%p: ", (void *)(address + curr_byte_idx));
                    }
                    printf("0x%.2x ", curr_dump_buff_subvec.at(curr_byte_idx));
                    if (!((curr_byte_idx + 1) % sizeof(void *))) {
                        std::cout << '\n';
                    }
                }
                // skip unnecessary blank line
                if (bytes_to_read % sizeof(void *)) {
                    std::cout << std::endl;
                }
            } else {
                fprintf(stderr, "Cannot read %lu bytes from address %p\n", bytes_to_read, (void *)address);
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
    }

    // Parses the loaded json and generates the memory map vector
    void Dumper::DumpInspector::generate_mem_vec_from_json() {
        memory_vec_t mem_map_vec {};
        unsigned long size_with_regs {}, raw_size {};
        std::vector<std::string> parsed_keys {};
        // collect all key values from the json file
        for (auto json_iter { loaded_json.cbegin() }; json_iter != loaded_json.cend(); ++json_iter) {
            parsed_keys.push_back(json_iter.key());
        }
        // parse values
        for (const auto &curr_key : parsed_keys) {
            MemoryMetadata curr_mem_metadata {};
            if (!curr_key.compare("RawDumpSize")) {
                loaded_json.at(curr_key).get_to(raw_size);
            } else if (!curr_key.compare("DumpWithRegsAppendix")) {
                loaded_json.at(curr_key).get_to(size_with_regs);
            } else {
                unsigned long rng_size {};
                loaded_json.at(curr_key).at("MemoryRangeSize").get_to(rng_size);
                loaded_json.at(curr_key).at("DumpBufferOffset").get_to(curr_mem_metadata.buffer_offset);
                loaded_json.at(curr_key).at("Permissions").get_to(curr_mem_metadata.mem_perms);
                loaded_json.at(curr_key).at("MemMapName").get_to(curr_mem_metadata.mem_name);
                curr_mem_metadata.mem_rng.first = std::stoul(curr_key, nullptr, 16); 
                curr_mem_metadata.mem_rng.second = curr_mem_metadata.mem_rng.first + rng_size;
                mem_map_vec.push_back(curr_mem_metadata);
            }
        }
        // constructs tuple <full dump, dump size + dumped regs appendix, raw memory dump size>
        parsed_json_data = std::make_tuple(mem_map_vec, size_with_regs, raw_size);
    }

    // Triggers dump inspection routine
    // Arguments: 1) Path to raw binary process dump
    //            2) Path to json file with a metadata about the dump
    void Dumper::inspect_dump(const std::string dump_path, const std::string json_path) {
        if (umd_mode == umdMode::INSPECT_MODE) {
            inspector_obj = new DumpInspector(dump_path, json_path);
            if (!inspector_obj) {
                std::cerr << "Cannot allocate dump inspector object" << std::endl;
                exit(EXIT_FAILURE);
            }
            inspector_obj->dump_inspection_mainloop();
        } else {
            std::cerr << "umd is not in inspect mode" << std::endl;
        }
    }

    // Triggers dump routine with attach mode
    // Argument: target PID to be dumped
    void Dumper::dump_process(const pid_t target_pid) {
        if (umd_mode == umdMode::ATTACH_MODE) {
            this->target_pid = target_pid;
            attach_to_process();     
        } else {
            std::cerr << "umd is not in attach mode" << std::endl;
        }
    }

    // Attach mode routine
    void Dumper::attach_to_process() {
        ptrace(PTRACE_ATTACH, target_pid, nullptr, nullptr); 
        std::cout << "Attached to PID " << target_pid << std::endl;
        auto mem_map_vec { parse_procmaps() }; 
        const std::string dump_path {_dump_process(mem_map_vec) };
        craft_json_dump(mem_map_vec, dump_path);
        // detaching allows the target process to continue the execution
        ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr); 
    }

    // Dumps the whole process memory dump to the disk
    // Argument: reference to the whole dump buffer (dumped memory + regs appendix)
    // Return value: full path to the json that will be associated with this dump
    const std::string Dumper::dump_mem_to_disk(const std::vector<uint8_t> &dump_buffer) const {
        std::string proc_name { std::to_string(target_pid) }, 
                    pwd { std::filesystem::current_path() },
                    dump_path { pwd + "/" + proc_name + "_dump" },
                    dump_name { proc_name + ".umd" };
        std::filesystem::path dump_fs_path(dump_path);
        // check if the directory already exists
        if (!std::filesystem::exists(dump_fs_path)) {
            std::filesystem::create_directory(dump_path); 
        }
        std::ofstream dump_ofstream(dump_path + "/" + dump_name);
        // write the raw dump to the disk
        printf("Dumping the raw dump [%s | size %lu bytes] to the disk [destination directory -> %s]...\n", dump_name.data(), 
                                                                                                            dump_buffer.size(), 
                                                                                                            dump_path.data());
        // dump to the disk
        dump_ofstream.write(reinterpret_cast<const char *>(&dump_buffer[0]), dump_buffer.size());
        dump_ofstream.close();
        return dump_path + "/" + proc_name + ".json";
    }


    // Calculates all contiguous memory regions locations
    // Argument: reference to the vector of memory metadata 
    // Return value: vector of pairs where the first value is contiguous start memory index in the vector of memory metadata
    //               and the second value is the size of the contiguous memory chunk
    // The method is needed for better multithreaded dumping routine utilization
    const Dumper::cont_mem_pairs_vec Dumper::get_cont_mem_indices(const memory_vec_t &mem_vec) const {
        cont_mem_pairs_vec cont_mem_vec {};
        if (mem_vec.size()) {
            if (mem_vec.size() == 1) { 
                cont_mem_vec.push_back({ 0, mem_vec.at(0).mem_rng.second - mem_vec.at(0).mem_rng.first });
                return cont_mem_vec;
            }
            bool cont_mem_flag { false };
            unsigned long cont_mem_start_idx {}, mem_idx {};
            for (; mem_idx < mem_vec.size() - 1; ++mem_idx) {
                auto curr_mem_rng_end_addr { mem_vec.at(mem_idx).mem_rng.second };
                auto next_mem_rng_start_addr { mem_vec.at(mem_idx + 1).mem_rng.first };
                if (curr_mem_rng_end_addr == next_mem_rng_start_addr) {
                    if (!cont_mem_flag) {
                        cont_mem_flag = true;
                        cont_mem_start_idx = mem_idx;
                    }
                } else {
                    if (cont_mem_flag) {
                        cont_mem_flag = false;
                        unsigned long cont_mem_size {};
                        for (unsigned long i { cont_mem_start_idx }; i <= mem_idx; ++i) {
                            cont_mem_size += (mem_vec.at(i).mem_rng.second - mem_vec.at(i).mem_rng.first);
                        } 
                        cont_mem_vec.push_back({ cont_mem_start_idx, cont_mem_size });
                    } else {
                        cont_mem_vec.push_back({ mem_idx, mem_vec.at(mem_idx).mem_rng.second - mem_vec.at(mem_idx).mem_rng.first });
                    }
                 }
              }
              if (cont_mem_flag) {
                  unsigned long cont_mem_size {};
                  for (unsigned long i { cont_mem_start_idx }; i <= mem_idx; ++i) {
                      cont_mem_size += (mem_vec.at(i).mem_rng.second - mem_vec.at(i).mem_rng.first);
                  } 
                  cont_mem_vec.push_back({ cont_mem_start_idx, cont_mem_size });
              } else {
                  cont_mem_vec.push_back({ mem_idx, mem_vec.at(mem_idx).mem_rng.second - mem_vec.at(mem_idx).mem_rng.first });
              }
        }
        return cont_mem_vec;
    }

    // Thread worker that reads the part of the before mentioned memory metadata vector 
    // in order to dispatch the right location in the vector of memory metadata to be parsed for the contiguous memory dump
    // No mutex required because each thread works on different iterator range (from start_iter to end_iter)
    // Arguments: 1) /proc/target_pid/mem file descriptor
    //            2) Reference to the memory metadata vector
    //            3) Reference to the dump buffer
    //            4) Start iterator in memory metadata vector
    //            5) End iterator in memory metadata vector
    void Dumper::dump_thread(const int procmem_fd, 
                             const memory_vec_t &mem_metadata, 
                             std::vector<uint8_t> &dump_buffer,
                             cont_mem_pairs_vec::const_iterator start_iter,
                             cont_mem_pairs_vec::const_iterator end_iter) const {
        while (start_iter != end_iter) {
            auto cont_mem_start_idx { start_iter->first };
            auto cont_mem_size { start_iter->second };
            pread(procmem_fd, 
                  &dump_buffer.at(mem_metadata.at(cont_mem_start_idx).buffer_offset), 
                  cont_mem_size, 
                  mem_metadata.at(cont_mem_start_idx).mem_rng.first);
            start_iter++;
        }
    }

    // Main dumping process routine
    // The dumping is multithreaded and designed as a thread pool
    // Argument: reference to the memory metadata vector
    // Return value: path to json file for the given memory dump
    const std::string Dumper::_dump_process(const memory_vec_t &mem_map_vec) const {
        std::string procmem_path { "/proc/" + std::to_string(target_pid) + "/mem" };
        int procmem_fd = open(procmem_path.data(), O_RDONLY);
        if (procmem_fd == -1) {
            fprintf(stderr, "Cannot open %s\n", procmem_path.data());
            ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
            exit(EXIT_FAILURE);
        }
        // allocate the buffer for the whole dump
        std::vector<uint8_t> dump_buffer(dump_size + sizeof(struct user_regs_struct));
        auto thread_cnt { std::thread::hardware_concurrency() };
        auto cont_mem_rng_indices_vec { get_cont_mem_indices(mem_map_vec) };
        auto thread_pool_cycles { cont_mem_rng_indices_vec.size() / thread_cnt };
        std::vector<std::thread> dump_thread_pool {};
        for (auto cont_mem_vec_iter { cont_mem_rng_indices_vec.cbegin() }; 
                  (cont_mem_vec_iter + thread_pool_cycles) < cont_mem_rng_indices_vec.cend(); 
                  cont_mem_vec_iter += thread_pool_cycles) {

            // thread pool invocation
            dump_thread_pool.push_back(std::thread(&Dumper::dump_thread, 
                                                   this, 
                                                   procmem_fd, 
                                                   std::ref(mem_map_vec), 
                                                   std::ref(dump_buffer),
                                                   cont_mem_vec_iter,
                                                   cont_mem_vec_iter + thread_pool_cycles));
        }
        // if the amount of memory mappings is not divided by the thread amount without remainder, dump the remained memory in the main thread
        auto thread_pool_remainder { cont_mem_rng_indices_vec.size() % thread_cnt };
        if (thread_pool_remainder) {
            auto vec_remainder_iter { cont_mem_rng_indices_vec.cend() - thread_pool_remainder };
            dump_thread(procmem_fd, mem_map_vec, dump_buffer, vec_remainder_iter, vec_remainder_iter + thread_pool_remainder); 
        }
        // wait for all dumping threads to join
        for (auto &thr : dump_thread_pool) {
            if (thr.joinable()) {
                thr.join();
            }
        }
        // dump the registers and append it to the memory dump
        struct user_regs_struct regs {};
        ptrace(PTRACE_GETREGS, target_pid, nullptr, &regs);
        std::memcpy(&dump_buffer.at(dump_size), &regs, sizeof(regs));
        close(procmem_fd);
        return dump_mem_to_disk(dump_buffer);
    }

    // Validates the memory access during dump inspection or breakpoint injection
    // Arguments: 1) Reference to memory metadata vector
    //            2) Address to read to/write from
    //            3) The amount of bytes to read/write
    // Return value: iterator to the memory metadata vector for the memory access, return end() if the access is invalid
    memory_vec_t::const_iterator valid_mem_access(const memory_vec_t &mem_map_vec,
                                                  const unsigned long address, 
                                                  const unsigned long mem_size) {

        ssize_t start {}, end { static_cast<ssize_t>(mem_map_vec.size() - 1) };
        // modified binary search 
        while (start <= end) {
            // famous binary search integer overflow prevention
            auto mid { (static_cast<size_t>(start) + static_cast<size_t>(end)) >> 1 };
            auto curr_vec_elem { mem_map_vec.at(mid) };
            auto curr_mem_rng_start { curr_vec_elem.mem_rng.first };
            auto curr_mem_rng_end { curr_vec_elem.mem_rng.second };
            if (curr_mem_rng_start <= address && curr_mem_rng_end > address) {
                auto cont_mem_start_vec_iter { mem_map_vec.cbegin() + mid };
                if ((address + mem_size) <= curr_mem_rng_end) {
                    return cont_mem_start_vec_iter;
                }
                auto vec_iter { cont_mem_start_vec_iter };
                while (vec_iter != mem_map_vec.cend()) {
                    if (vec_iter + 1 != mem_map_vec.cend() && (vec_iter + 1)->mem_rng.first == curr_mem_rng_end) {
                        vec_iter++;
                        curr_mem_rng_end = vec_iter->mem_rng.second;
                        if ((address + mem_size) <= curr_mem_rng_end) {
                            return cont_mem_start_vec_iter; 
                        }
                    } else {
                        return mem_map_vec.cend();
                    }
                }
                return mem_map_vec.cend();
            } else if (curr_mem_rng_start > address) {
                end = mid - 1;
            } else {
                start = mid + 1;
            }
        }
        return mem_map_vec.cend();
    }

    // /proc/target_pid_maps parsing routine
    // Return value: memory metadata vector
    const memory_vec_t Dumper::parse_procmaps() {
        std::string procmaps_path { "/proc/" + std::to_string(target_pid) + "/maps" };
        std::ifstream procmaps_ifstream { procmaps_path };
        if (!procmaps_ifstream.is_open()) {
            fprintf(stderr, "Cannot open %s\n", procmaps_path.data());
            ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr); 
            exit(EXIT_FAILURE);
        }
        // be sure that dump size is zero before procmaps parsing
        dump_size = 0;
        memory_vec_t memory_map {};
        std::string line {};
        unsigned long curr_offset {};
        while (std::getline(procmaps_ifstream, line)) {
            // parse memory range
            std::stringstream ss(line);
            std::string curr_token {};
            unsigned token_idx {};
            MemoryMetadata curr_mem_metadata {};
            unsigned long curr_mem_rng_start_addr {};
            while (std::getline(ss, curr_token, ' ')) {
                if (curr_token.size()) {
                    switch (token_idx) {
                        case MEM_RNG_TOKEN_IDX: {
                            auto hyphen_idx { curr_token.find('-') };
                            curr_mem_metadata.mem_rng.first = std::stoul(curr_token.substr(0, hyphen_idx), nullptr, 16);
                            curr_mem_metadata.mem_rng.second = std::stoul(curr_token.substr(hyphen_idx + 1), nullptr, 16); 
                            curr_mem_metadata.buffer_offset = curr_offset;
                            auto curr_mem_rng_size { curr_mem_metadata.mem_rng.second - curr_mem_metadata.mem_rng.first };
                            curr_offset += curr_mem_rng_size;
                            dump_size += curr_mem_rng_size;
                        }
                            break;
                        case MEM_PERMS_TOKEN_IDX:
                            curr_mem_metadata.mem_perms = curr_token;
                            break;
                        case MEM_NAME_TOKEN_IDX:
                            curr_mem_metadata.mem_name = curr_token;
                            break;
                        default:
                            break;
                    }
                    token_idx++;
                }
            }
            memory_map.push_back(curr_mem_metadata);
        }
        procmaps_ifstream.close();
        return memory_map;
    }

    // JSON file dumping routine
    // Arguments: 1) Reference to memory metadata vector
    //            2) Reference to a full path for this JSON file
    void Dumper::craft_json_dump(const memory_vec_t &mem_map_vec, const std::string &json_dump_filename) const {
        std::ofstream json_dump_ofstream { json_dump_filename };
        if (!json_dump_ofstream.is_open()) {
            fprintf(stderr, "Cannot open ofstream for this path -> %s\n", json_dump_filename.data());
            ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
            exit(EXIT_FAILURE);
        }
        json json_dump_obj {};
        for (const auto &mem_vec_node : mem_map_vec) {
            std::stringstream ss {};
            ss << "0x" << std::hex << mem_vec_node.mem_rng.first;
            auto curr_mem_rng_size { mem_vec_node.mem_rng.second - mem_vec_node.mem_rng.first };
            json_dump_obj[ss.str()] = {
                { "MemoryRangeSize", curr_mem_rng_size },
                { "DumpBufferOffset", mem_vec_node.buffer_offset }, 
                { "Permissions", mem_vec_node.mem_perms },
                { "MemMapName", mem_vec_node.mem_name }
            };
        } 
        json_dump_obj["RawDumpSize"] = dump_size;
        json_dump_obj["DumpWithRegsAppendix"] = dump_size + sizeof(struct user_regs_struct);
        // serialize the json file
        json_dump_ofstream << json_dump_obj.dump(4);
        json_dump_ofstream.close();
    }
}
