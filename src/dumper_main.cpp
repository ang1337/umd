#include "../include/dumper.hpp"
#include <iostream>
#include <sys/user.h>
#include <unistd.h>
#include <memory>

void show_usage(char **argv) {
    fprintf(stderr, "Usage: %s <[-a <PID>] [-i <path to memory dump> <path to JSON memory metadata file>]>\n", argv[0]);
}

const umd::umdMode validate_args(int argc, char **argv) {
    char opt {};
    umd::umdMode dump_mode {};
    while ((opt = getopt(argc, argv, "a:i")) != -1) {
        switch (opt) {
            case 'a':
                dump_mode = umd::umdMode::ATTACH_MODE;
                break;
            case 'i':
                dump_mode = umd::umdMode::INSPECT_MODE; 
                break;
            case '?':
            default:
                show_usage(argv);
                exit(EXIT_FAILURE);
        }
    }
    return dump_mode;
}

int main(int argc, char **argv, char **envp) {
    if (argc < 3) {
        show_usage(argv);
        exit(EXIT_FAILURE);
    }
    umd::umdMode dump_mode { validate_args(argc, argv) };
    if ((dump_mode == umd::umdMode::ATTACH_MODE) && getuid()) {
        std::cerr << "Attach mode requires root privileges." << std::endl;
        exit(EXIT_FAILURE);
    }
    std::unique_ptr<umd::Dumper> umd_obj { std::make_unique<umd::Dumper>(dump_mode) }; 
    switch (umd_obj->umd_mode) {
        case umd::umdMode::ATTACH_MODE: {
            const pid_t target_pid { std::stoi(argv[2]) };
            umd_obj->dump_process(target_pid);
            break;
        }
        case umd::umdMode::INSPECT_MODE: {
            umd_obj->inspect_dump(argv[2], argv[3]);
            struct user_regs_struct regs {};
            // optional: get dumped regs
            umd_obj->get_dumped_regs(regs);
            break;
        }
    }
    return 0;
}
