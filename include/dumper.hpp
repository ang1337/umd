#pragma once 
#include <string>
#include <nlohmann/json.hpp>
#include <sys/user.h>
#include <sys/types.h>
#include <sstream>
#include <iostream>
#include <vector>
#include <tuple>

namespace umd {

    enum class umdMode {
        ATTACH_MODE,
        INSPECT_MODE
    };

    // memory mapping metadata relevant for the dump
    struct MemoryMetadata {
        // start and end memory range addresses
        std::pair<unsigned long, unsigned long> mem_rng;
        // offset in dump buffer
        unsigned long buffer_offset;
        // memory range permissions and name
        std::string mem_perms,
                    mem_name;
    };

    using json = nlohmann::json;
    using memory_vec_t = std::vector<MemoryMetadata>;

    memory_vec_t::const_iterator valid_mem_access(const memory_vec_t &, const unsigned long, const unsigned long);
    template <typename GenType>
    void process_input(GenType &input_var, const std::string &&);

    class Dumper {
        public:
            const umdMode umd_mode;
            Dumper(const umdMode);
            ~Dumper();
            void dump_process(const pid_t);
            void inspect_dump(const std::string, const std::string);
            void get_dumped_regs(struct user_regs_struct &) const;
        private:
            // relevant token indices in procmaps output
            enum {
                MEM_RNG_TOKEN_IDX = 0,
                MEM_PERMS_TOKEN_IDX = 1,
                MEM_NAME_TOKEN_IDX = 5
            };
            using cont_mem_pairs_vec = std::vector<std::pair<unsigned long, unsigned long>>;
            const cont_mem_pairs_vec get_cont_mem_indices(const memory_vec_t &) const;

            class DumpInspector {
                public:
                    struct user_regs_struct dumped_regs;
                    DumpInspector(const std::string &, const std::string &);
                    ~DumpInspector() = default;
                    void dump_inspection_mainloop() const;
                private:
                    // tuple indices
                    enum {
                        TUPLE_MEM_MAP_IDX,
                        TUPLE_SIZE_WITH_REGS_IDX,
                        TUPLE_RAW_SIZE_IDX
                    };
                    std::tuple<memory_vec_t, unsigned long, unsigned long> parsed_json_data;
                    json loaded_json;
                    std::vector<uint8_t> dump_buffer;
                    void extract_dumped_regs();
                    void generate_mem_vec_from_json();
            };
            DumpInspector *inspector_obj;
            // 0xcc opcode 
            const unsigned char intel_arch_bp_opcode;
            pid_t target_pid;
            unsigned long dump_size;
            void dump_thread(const int, 
                             const memory_vec_t &, 
                             std::vector<uint8_t> &,
                             cont_mem_pairs_vec::const_iterator, 
                             cont_mem_pairs_vec::const_iterator) const;
            const memory_vec_t parse_procmaps();
            void craft_json_dump(const memory_vec_t &, const std::string &) const;
            void attach_to_process();
            void restore_original_byte(const unsigned long, const uint8_t);
            const std::string _dump_process(const memory_vec_t &) const;
            const std::string dump_mem_to_disk(const std::vector<uint8_t> &) const;
    };
}

// generic input handling function
template <typename GenType>
void umd::process_input(GenType &input_var, const std::string &&prompt) {
    std::cout << prompt; 
    std::string temp_io_str {};
    std::getline(std::cin, temp_io_str);
    std::stringstream ss(temp_io_str);
    ss >> input_var;
}
