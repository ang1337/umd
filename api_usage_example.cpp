#include "inc/Dumper.hpp"
#include <iostream>
#include <sys/types.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <target PID>\n", argv[0]);
        exit(1);
    }
    try {
        umd::Dumper dump_obj(std::stoi(argv[1]));
        const auto res { dump_obj.dump_memory() };
        dump_obj.dump_to_disk(res, "/home/user/test_dump.umd");
        auto memchunk { dump_obj.inspect_memory(res, 0x560ad88ea000, 20) };
        if (memchunk.has_value()) {
            for (const auto byte : *memchunk) {
                printf("0x%.2x ", byte);
            }
            std::cout << std::endl;
        } 
    } catch (const umd::umd_exception &e) {
        std::cerr << e.what() << std::endl;
    }
}