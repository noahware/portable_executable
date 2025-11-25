#pragma once

#include <cstdint>
#include <string>

namespace portable_executable
{
    union delay_load_attributes_t
    {
	    struct
	    {
            std::uint32_t rva_based : 1;
            std::uint32_t reserved : 31;
	    };

        std::uint32_t flags;
    };

    struct delay_load_descriptor_t
    {
        delay_load_attributes_t attributes;
        std::uint32_t dll_name_rva;
        std::uint32_t module_handle_rva;
        std::uint32_t import_address_table_rva;
        std::uint32_t import_name_table_rva;
        std::uint32_t bound_import_address_table_rva;
        std::uint32_t unload_information_table_rva;
        std::uint32_t time_date_stamp;

        [[nodiscard]] bool rva_based() const
        {
            return attributes.rva_based;
        }

        [[nodiscard]] std::uint32_t get_original_first_thunk() const
        {
            return import_name_table_rva;
        }

        [[nodiscard]] std::uint32_t get_first_thunk() const
        {
            return import_address_table_rva;
        }

        [[nodiscard]] std::uint32_t get_name() const
        {
            return dll_name_rva;
        }
    };
}