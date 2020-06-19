#include "../include/Validator.h"
#include <cstdlib>
#include <iostream>
#include <cstring>
#include <filesystem>
#include <algorithm>
#include <fstream>
#include <limits>

/* validates if string represents posivite integer value */
bool input_validation::is_positive_number(const std::string &s) {
    return !s.empty() && std::find_if(s.begin(), 
                                      s.end(),
                                      [](unsigned char c) { 
                                        return !std::isdigit(c); 
                                      }) == s.end();
}

/* main arguments validation routine */
bool input_validation::validate_args(char** const argv) {
    if (!strcmp(argv[2], "-i") || !strcmp(argv[2], "--inspect")) {
        return !is_binary(argv[1]) && is_binary(argv[3]);
    } 
    const std::string dump_dir { argv[1] };
    if (!std::filesystem::exists(dump_dir)) {
        std::filesystem::create_directory(dump_dir);
        if (!std::filesystem::exists(dump_dir)) {
            std::cerr << "Dump directory creation failure" << std::endl;
            return false;
        }
    }
    if ((strcmp(argv[2], "-a") && strcmp(argv[2], "--attach")) || !is_positive_number(argv[3])) {
            return false;
    }
    return true;
}

void input_validation::handle_invalid_iostream() noexcept {
    std::flush(std::cout);
    std::cerr << "Invalid input value" << std::endl;
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

bool input_validation::is_binary(const std::string path_to_file) noexcept {
    std::ifstream file_istream { path_to_file, std::ios::binary };
    if (!file_istream || !file_istream.good()) {
        std::cerr << "ERROR : cannot open the file " + path_to_file << std::endl;
        exit(EXIT_FAILURE);
    }
    char byte {};
    const unsigned char last_ascii_char { 0x7f };
    while (!file_istream.eof()) {
        file_istream.get(byte);
        if (static_cast<unsigned char>(byte) > last_ascii_char) {
            return true;
        }
    }
    return false;
}

void input_validation::show_usage(char** const argv) {
    std::cerr << "Usage : " << argv[0] << " [path to dump directory | path to memory layout file] [-a OR --attach | -i OR --inspect] [pid to attach OR path to memory dump]" << std::endl;
}
