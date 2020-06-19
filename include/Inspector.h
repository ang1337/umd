#pragma once
#include <cstdint>
#include <vector>
#include <utility>
#include "../include/Dumper.h"

class Inspector {
    public:
        Inspector(std::vector<AddressRangeInfo>&);
        ~Inspector() = default;
        void map_address_space() noexcept;
        std::uint64_t get_offset(const std::uint64_t) const noexcept;
        std::vector<std::uint8_t> read_memory(const std::vector<std::uint8_t>&, const std::uint64_t, const std::uint64_t) const noexcept;
        std::uint16_t check_machine_type(const std::vector<std::uint8_t>&) const noexcept;
    private:
        const std::uint16_t machine_type_ehdr_offset;
        std::vector<AddressRangeInfo> &proc_maps_info;
};

