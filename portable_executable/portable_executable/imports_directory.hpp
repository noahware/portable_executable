#pragma once

#include <cstdint>
#include <string>
#include <iterator>
#include <optional>

namespace portable_executable
{
    struct import_descriptor_t
    {
        union
        {
            std::uint32_t characteristics;
            std::uint32_t original_first_thunk;
        } misc;

        std::uint32_t time_date_stamp;
        std::uint32_t forwarder_chain;
        std::uint32_t name;
        std::uint32_t first_thunk;

        [[nodiscard]] std::uint32_t get_original_first_thunk() const
        {
            return misc.original_first_thunk;
        }

        [[nodiscard]] std::uint32_t get_first_thunk() const
        {
            return first_thunk;
        }

        [[nodiscard]] std::uint32_t get_name() const
        {
            return name;
        }
    };

    struct thunk_data_t
    {
        union
        {
            std::uint64_t forwarder_string;
            std::uint64_t function;
            std::uint64_t address;

            struct  // NOLINT(clang-diagnostic-nested-anon-types)
            {
                std::uint64_t ordinal : 16;
                std::uint64_t reserved0 : 47;
                std::uint64_t is_ordinal : 1;
            };
        };
    };

    struct import_by_name_t
    {
        std::uint16_t hint;
        char name[1];
    };

    struct import_entry_t
    {
        std::string module_name;

        // Set for a name import, empty for an ordinal import.
        std::string name;

        // Set for an ordinal import, zero for a name import.
        std::uint16_t ordinal_value;

        bool is_ordinal;

        std::uint8_t*& address;

        // Empty when the import is by ordinal -- such an import carries no name.
        [[nodiscard]] std::string import_name() const
        {
            return this->name;
        }

        // Nullopt when the import is by name. This is the form GetProcAddress
        // accepts, via MAKEINTRESOURCE.
        [[nodiscard]] std::optional<std::uint16_t> ordinal() const
        {
            if (!this->is_ordinal)
            {
                return std::nullopt;
            }

            return this->ordinal_value;
        }
    };

    template<typename T>
    class imports_iterator_t
    {
        const std::uint8_t* m_module = nullptr;

        const T* m_current_descriptor = nullptr;
        const thunk_data_t* m_current_thunk = nullptr;
        const thunk_data_t* m_original_thunk = nullptr;

    public:
        imports_iterator_t(const std::uint8_t* module, const std::uint8_t* descriptor) :
            m_module(module), m_current_descriptor(reinterpret_cast<const T*>(descriptor))
        {
            if (this->m_current_descriptor && this->m_current_descriptor->get_first_thunk())
            {
                this->m_current_thunk = reinterpret_cast<const thunk_data_t*>(this->m_module + this->m_current_descriptor->get_first_thunk());
                this->m_original_thunk = reinterpret_cast<const thunk_data_t*>(this->m_module + this->m_current_descriptor->get_original_first_thunk());
            }
        }

        using iterator_category = std::forward_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using value_type = import_entry_t;
        using pointer = value_type*;
        using reference = value_type&;

        value_type operator*() const
        {
            std::string name;
            std::uint16_t ordinal_value = 0;

            const bool is_ordinal = this->m_original_thunk->is_ordinal;

            if (is_ordinal)
            {
                // An ordinal import has no name string. The low 16 bits are the
                // ordinal number itself, not an RVA, so it must not be dereferenced.
                ordinal_value = static_cast<std::uint16_t>(this->m_original_thunk->ordinal);
            }
            else
            {
                const auto import_by_name = reinterpret_cast<const import_by_name_t*>(this->m_module + this->m_original_thunk->address);

                name = import_by_name->name;
            }

            const std::string module_name(reinterpret_cast<const char*>(this->m_module + this->m_current_descriptor->get_name()));

            auto* import_addr_ref = const_cast<std::uint64_t*>(&this->m_current_thunk->function);
            auto& import_addr = *reinterpret_cast<std::uint8_t**>(import_addr_ref);

            return { module_name, name, ordinal_value, is_ordinal, import_addr };
        }

        imports_iterator_t& operator++()
        {
            if (this->m_current_thunk && this->m_current_thunk->address)
            {
                ++this->m_current_thunk;
                ++this->m_original_thunk;

                if (!this->m_current_thunk->address)
                {
                    ++this->m_current_descriptor;

                    while (this->m_current_descriptor && this->m_current_descriptor->get_first_thunk())
                    {
                        this->m_current_thunk = reinterpret_cast<const thunk_data_t*>(this->m_module + this->m_current_descriptor->get_first_thunk());
                        this->m_original_thunk = reinterpret_cast<const thunk_data_t*>(this->m_module + this->m_current_descriptor->get_original_first_thunk());

                        if (this->m_current_thunk->address)
                        {
                            break;
                        }

                        ++this->m_current_descriptor;
                    }

                    if (!this->m_current_descriptor || !this->m_current_descriptor->get_first_thunk())
                    {
                        this->m_current_descriptor = nullptr;
                        this->m_current_thunk = nullptr;
                    }
                }
            }

            return *this;
        }

        bool operator==(const imports_iterator_t& other) const
        {
            return this->m_current_descriptor == other.m_current_descriptor && this->m_current_thunk == other.m_current_thunk;
        }

        bool operator!=(const imports_iterator_t& other) const
        {
            return this->m_current_descriptor != other.m_current_descriptor || this->m_current_thunk != other.m_current_thunk;
        }
    };
    
    template<typename T>
    class imports_range_t
    {
    private:
        using pointer_type = std::conditional_t<std::is_const_v<T>, const std::uint8_t*, std::uint8_t*>;

        pointer_type m_module = nullptr;

        const std::uint8_t* m_import_descriptor = nullptr;

    public:
        imports_range_t() = default;

        imports_range_t(pointer_type module, std::uint32_t imports_rva) :
            m_module(module), m_import_descriptor(reinterpret_cast<const std::uint8_t*>(module + imports_rva))
        {

        }

        T begin() const
        {
            return { this->m_module, this->m_import_descriptor };
        }

        T end() const
        {
            return { this->m_module, nullptr };
        }
    };
}