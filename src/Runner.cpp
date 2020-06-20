#include <csignal>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <iostream>
#include <iomanip>
#include "../include/Validator.h"
#include "../include/Inspector.h"
#include "../include/Runner.h"
#include "../include/Dumper.h"

Runner::Runner(char** const passed_args) : args(passed_args) {
    std::string run_op { args[1] };
    /* attach mode */
    if (!(run_op.compare("-a")) || !(run_op.compare("--attach"))) {
        mode_fptr = &Runner::run_attach_mode;
        dump_dir = args[0];
        std::string string_pid { args[2] };
        target_pid = std::stoi(string_pid); 
    } else { // inspect mode 
        mode_fptr = &Runner::run_inspect_mode;
        path_to_memory_layout = args[0];
        path_to_dump = args[2];
    }
}

/* this method calls either attach or inspect mode method */
void Runner::run() noexcept {
    mode_fptr(*this);
}

void Runner::run_attach_mode() noexcept {
    int status {};
    ptrace(PTRACE_ATTACH, target_pid, nullptr, nullptr);
    waitpid(target_pid, &status, 0);
    if (WIFSTOPPED(status)) {
        if (WSTOPSIG(status) == SIGSTOP) {
            mem_dumper = std::make_unique<Dumper>(target_pid);
            mem_dumper->dump_memory(target_pid, dump_dir);
            prompt_for_inspection(mem_dumper);
            ptrace(PTRACE_DETACH, target_pid, nullptr, nullptr);
        } else {
            std::cerr << "The program has been stopped due to unexpected signal" << std::endl;
        }
    } else {
        std::cerr << "ERROR : PTRACE_ATTACH failure" << std::endl;
    }
}

void Runner::run_inspect_mode() noexcept {
    mem_dumper = std::make_unique<Dumper>(path_to_memory_layout, path_to_dump);
    std::cout << "Inspect mode" << "\nLoaded files:\nDump: " << path_to_dump
              << "\nMemory layout: " << path_to_memory_layout << std::endl;
    prompt_for_inspection(mem_dumper);
}

void Runner::print_memory_chunk(const std::vector<std::uint8_t> &memory_dump, 
                                std::uint64_t address, 
                                const std::uint64_t read_start_idx,
                                const std::uint64_t read_end_idx,
                                const std::uint16_t ptr_size) const noexcept {
    std::uint64_t up_to_idx { ptr_size };
    for (std::size_t i { read_start_idx }; i < read_end_idx; i += ptr_size) {
        std::cout << std::hex << address << std::dec << " :\t";
        if ((i + ptr_size) > read_end_idx) {
            up_to_idx = read_end_idx - i;
        }
        for (auto j { i }; j < (i + up_to_idx); j++) {
            printf("0x%x\t", memory_dump.at(j));
        }
        address += ptr_size;
        std::cout << '\n';
    }
}

/* main dump inspection routine */
void Runner::prompt_for_inspection(const std::unique_ptr<Dumper> &mem_dump_obj) noexcept {
    Inspector* inspector { mem_dump_obj->get_inspector_obj() };
    const std::vector<std::uint8_t> &memory_dump { mem_dump_obj->get_memory_dump() };
    unsigned char choice {};
    while (true) {
        std::cout << "Would you like to inspect the dump right now? (y/n) -> ";
        std::cin >> choice;
        if (choice == 'y') {
            std::uint64_t address {},
                          bytes_to_read {};
        prompt_another_address:
            std::cout << "Enter the address -> ";
            std::cin >> std::hex >> address >> std::dec;
            if (std::cin.fail()) {
                input_validation::handle_invalid_iostream();
                goto prompt_another_address;
            }
            std::cout << "How many bytes to read? -> ";
            std::cin >> bytes_to_read;
            if (std::cin.fail()) {
                input_validation::handle_invalid_iostream();
                goto prompt_another_address;
            }
            /* Check if the provided address and amount bytes to read are in memory layout boundaries */
            if (mem_dump_obj->is_in_range(address, bytes_to_read)) {
                const std::uint64_t read_start_idx { inspector->get_offset(address) },
                                    read_end_idx { read_start_idx + bytes_to_read };
                std::cout << "Memory chunk that starts at address " 
                          << std::hex << address << std::dec 
                          << std::endl;
                std::uint16_t ptr_size { inspector->check_machine_type(memory_dump) }; 
                print_memory_chunk(memory_dump, address, read_start_idx, read_end_idx, ptr_size);
            } else {
                std::flush(std::cout);
                std::cerr << "Cannot read " << bytes_to_read 
                          << " bytes from " << std::hex << address << std::dec  
                          << ", try to choose another address and/or amount of bytes to read"
                          << std::endl;
                goto prompt_another_address;
            }
        } else if (choice == 'n') {
            break;
        } else {
            std::cerr << "Invalid choice!" << std::endl;
        }
    }
}
