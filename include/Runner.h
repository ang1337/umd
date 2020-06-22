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
        std::ifstream dump_istream;
        std::string dump_dir,
                    path_to_dump,
                    path_to_memory_layout;
        char** const args;
        std::function<void(Runner&)> mode_fptr;
        pid_t target_pid;
        void run_attach_mode() noexcept;
        void run_inspect_mode() noexcept;
        void prompt_for_inspection(const std::unique_ptr<Dumper>&) noexcept;
        void print_memory_chunk(const std::vector<std::uint8_t>&, std::uint64_t, const std::uint64_t, const std::uint64_t, const std::uint16_t) const noexcept;
};
