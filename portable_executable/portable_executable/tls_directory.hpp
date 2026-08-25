#pragma once

#include <cstdint>
#include <cstddef>

namespace portable_executable
{
    union tls_characteristics_t
    {
        struct
        {
            std::uint32_t _pad0 : 20;
            std::uint32_t alignment : 4;
            std::uint32_t _pad1 : 8;
        };

        std::uint32_t flags;
    };

    struct tls_directory_t
    {
        using value_type = std::uint64_t; // x86 uses std::uint32_t

        value_type start_address_of_raw_data;
        value_type end_address_of_raw_data;
        value_type address_of_index;
        value_type address_of_call_backs;
        std::uint32_t size_of_zero_fill;
        tls_characteristics_t characteristics;
    };

    static_assert(offsetof(tls_directory_t, address_of_call_backs) == 0x18);
    static_assert(sizeof(tls_directory_t) == 40);
}
