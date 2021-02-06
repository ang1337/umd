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
        // create umd object passing a target PID as an argument
        umd::Dumper dump_obj(std::stoi(argv[1]));

        // dump the whole memory of a target process
        const auto res { dump_obj.dump_memory() };

        // print out formatted info about dumped memory
        std::cout << res;

        // save the dump to disk at the given path
        dump_obj.dump_to_disk(res, "/home/user/test_dump.umd");

        // read X bytes from virtual address Y of the dumped process memory
        auto mem_chunk { dump_obj.inspect_memory(res, 0xdeadbeefcafebabe, 1337) };

        // if there is no out-of-bound read, byte vector of the memory to inspect is returned from 'inspect_memory' method
        if (mem_chunk.has_value()) {
            std::cout << "Successfully read 1337 bytes from address 0xdeadbeefcafebabe:\n";

            for (const auto byte : *mem_chunk) {
                std::cout << byte << ' ';
            }

            std::cout << std::endl;

        } else { // out-of-bound read, change virtual address and/or amount of bytes to read
            std::cerr << "Cannot read 1337 bytes from address 0xdeadbeefcafebabe\n";
        }

    } catch (const umd::umd_exception &e) { // catch umd_exception if something goes terribly wrong
        std::cerr << e.what() << std::endl;
    }

    return 0;
}
