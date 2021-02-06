/* compiled with: g++ api_usage_example.cpp -lumd -lpthread -std=c++17 -O3 -o api_usage_example */
#include <umd/Dumper.hpp>
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
    } catch (const umd::umd_exception &e) {
        std::cerr << e.what() << std::endl;
    }
}
