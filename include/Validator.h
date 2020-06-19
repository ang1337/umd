#pragma once
#include <string>

namespace input_validation {
    bool is_positive_number(const std::string&);
    bool validate_args(char** const);
    void show_usage(char** const);
    void handle_invalid_iostream() noexcept;
    bool is_binary(const std::string) noexcept;
}
