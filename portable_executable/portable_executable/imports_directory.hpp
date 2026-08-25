#pragma once

#include <cstdint>
#include <string>
#include <iterator>
#include <optional>
#include <vector>
#include <ranges>
#include <span>
#include <cstring>
#include <unordered_map>
#include <string_view>
#include <algorithm>

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

        // RVA of this import's slot in the image's import address table. Zero
        // for a synthesised entry that has no existing table.
        std::uint32_t iat_slot_rva;

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

            // Where this import's IAT slot lives, relative to the image base.
            // Rebuilding the directory needs it to keep descriptors pointing at
            // the table the compiled call sites already reference.
            const auto iat_slot_rva = static_cast<std::uint32_t>(
                reinterpret_cast<const std::uint8_t*>(this->m_current_thunk) - this->m_module);

            return { module_name, name, ordinal_value, is_ordinal, iat_slot_rva };
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

    // Builds an import directory for placement at dir_rva. Descriptors, thunks
    // and name entries all reference each other by RVA, so the blob is only
    // valid at the address it was built for.
    //
    // first_thunk comes from iat_slot_rva, keeping descriptors pointed at the
    // table the image's code already calls through. No new IAT is allocated.
    //
    // The loader pairs thunk i with the slot at first_thunk + i * 8, so a thunk
    // is placed by its slot rva rather than by its position in the input. Order
    // therefore does not matter, but a module's slots must be contiguous: a gap
    // leaves a zero thunk, which terminates the array early.
    [[nodiscard]] inline std::pair<std::uint32_t, std::vector<std::uint8_t>> build_imports_directory(const std::span<const import_entry_t> imports, const std::uint32_t rva)
    {
        std::vector<std::uint8_t> bytes;

        const auto insert = [&]<typename T>(const T & v) -> std::uint32_t
        {
            const auto old_size = static_cast<std::uint32_t>(bytes.size());

            if constexpr (std::ranges::contiguous_range<T>)
            {
                using value_t = std::ranges::range_value_t<T>;
                static_assert(std::is_trivially_copyable_v<value_t>);

                const auto* base = reinterpret_cast<const std::uint8_t*>(std::ranges::data(v));

                bytes.insert(bytes.end(), base,
                    base + std::ranges::size(v) * sizeof(value_t));
            }
            else
            {
                static_assert(std::is_trivially_copyable_v<T>);

                const auto* base = reinterpret_cast<const std::uint8_t*>(&v);

                bytes.insert(bytes.end(), base, base + sizeof(T));
            }

            return rva + old_size;
        };

        struct module_info
        {
            std::vector<const import_entry_t*> imps;
        };

        std::unordered_map<std::string, module_info> modules;

        for (const auto& imp : imports)
        {
            auto& mod = modules[imp.module_name];

            mod.imps.push_back(&imp);
        }
        
        for (auto& mod : modules | std::views::values)
        {
            std::ranges::sort(mod.imps, {}, &import_entry_t::iat_slot_rva);
        }
    	
        const auto is_contiguous = [](const import_entry_t* a, const import_entry_t* b)
            {
                const std::uint32_t expected_next_rva = a->iat_slot_rva + sizeof(std::uint64_t);

                return b->iat_slot_rva == expected_next_rva;
            };

        const auto make_desc = [&](const std::string& mod_name, const std::span<const import_entry_t*> entries) -> import_descriptor_t
            {
                if (entries.empty())
                {
                    return { };
                }

                import_descriptor_t d;

                const std::uint32_t name_rva = insert(std::span{ mod_name.c_str(), mod_name.size() + 1 });

                std::vector<std::uint32_t> ints;
                ints.reserve(entries.size() + 1);

                for (const auto e : entries)
                {
                    // import_by_name_t
                    std::uint16_t hint = 0;

                    ints.push_back(insert(hint));
	                insert(std::span{ e->name.c_str(), e->name.size() + 1 });
                }

                ints.push_back(0);

                d.name = name_rva;
                d.time_date_stamp = 0;
                d.forwarder_chain = 0;
                d.first_thunk = entries[0]->iat_slot_rva;
                d.misc.original_first_thunk = insert(ints);

                return d;
            };

        std::vector<import_descriptor_t> descriptors;
        descriptors.reserve(modules.size());

        for (auto& [name, info] : modules)
        {
            std::vector<const import_entry_t*> pending_imps;

            const auto flush = [&]()
                {
                    if (pending_imps.empty())
                    {
                        return;
                    }

                    descriptors.push_back(make_desc(name, pending_imps));
                };

            const import_entry_t* last = nullptr;

	        while (!info.imps.empty())
	        {
                const auto curr = info.imps.back();
                info.imps.pop_back();

                if (last != nullptr && is_contiguous(last, curr))
                {
                    flush();
                    pending_imps.clear();
                }

                pending_imps.push_back(curr);
                last = curr;
	        }

            flush();
        }

        const std::uint32_t dir_rva = insert(descriptors);

        return { dir_rva, bytes };
    }
}