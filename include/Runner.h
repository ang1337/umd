#pragma once
#include <cstdint>
#include <fstream>
#include <functional>
#include <memory>
#include "Dumper.h"

class Runner {
    public:
        Runner(char** const);
        Runner(char* const);
        ~Runner() = default;
        void run() noexcept;
    private:
        std::unique_ptr<Dumper> mem_dumper;
        void run_attach_mode() noexcept;
        void run_inspect_mode() noexcept;
        void prompt_for_investigation(const std::unique_ptr<Dumper>&) noexcept;
        void inspect_chunk(std::vector<std::uint8_t>&) noexcept;
        void print_memory_chunk(const std::vector<std::uint8_t>&, std::uint64_t, const std::uint16_t) const noexcept;
        pid_t target_pid;
        std::function<void(Runner&)> mode_fptr;
        std::string dump_dir,
                    path_to_dump,
                    path_to_memory_layout;
        std::ifstream dump_istream;
        char** const args;
};
