#pragma once

#include <cstdint>
#include <string>
#include <iterator>

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
        std::string import_name;
        std::uint8_t*& address;
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
            std::string import_name;

            if (this->m_original_thunk->is_ordinal)
            {
                import_name = reinterpret_cast<const char*>(this->m_module + this->m_original_thunk->ordinal);
            }
            else
            {
                const auto import_by_name = reinterpret_cast<const import_by_name_t*>(this->m_module + this->m_original_thunk->address);

                import_name = import_by_name->name;
            }

            const std::string module_name(reinterpret_cast<const char*>(this->m_module + this->m_current_descriptor->get_name()));

            auto* import_addr_ref = const_cast<std::uint64_t*>(&this->m_current_thunk->function);
            auto& import_addr = *reinterpret_cast<std::uint8_t**>(import_addr_ref);

            return { module_name, import_name, import_addr };
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