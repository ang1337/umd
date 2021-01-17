#pragma once
#include <string>
#include <exception>
#include <stdexcept>

namespace umd {
    class umd_exception : public std::exception {
        private:
            const std::string _err_msg;
        public:
            umd_exception(const std::string &err_msg) : _err_msg(err_msg) {}
            const char* what() const noexcept override {
                return _err_msg.data();
            }
    };
}