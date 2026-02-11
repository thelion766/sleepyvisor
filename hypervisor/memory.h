#include "tools.h"

namespace memory
{
    void* MmAllocateIndependentPages(std::size_t number_of_bytes)
    {
        if (!number_of_bytes)
            return nullptr;
        void* nt_base = reinterpret_cast<void*>(get_nt_base());
        if (!nt_base)
            return nullptr;
        std::size_t nt_size = tools::get_module_size(nt_base);
        void* function = tools::find_pattern(reinterpret_cast<unsigned char*>(nt_base), nt_size, "48 8B C4 48 89 58 10 44 89 48 20 55 56 57 41 54 41 55 41 56 41 57 48 81 EC");
        if (!function)
            return nullptr;
        typedef void* (__fastcall* MmAllocateIndependentPages_t)(std::uint64_t, std::uint32_t, std::uint64_t, std::uint64_t);
        MmAllocateIndependentPages_t page_alloc = reinterpret_cast<MmAllocateIndependentPages_t>(function);
        void* value = page_alloc(number_of_bytes, -1, 0, 0);
        return value;
    }


    void MmFreeIndependentPages(void* base_address, std::size_t number_of_bytes)
    {
        if (!base_address || !number_of_bytes)
            return;
        void* nt_base = reinterpret_cast<void*>(get_nt_base());
        if (!nt_base)
            return;
        std::size_t nt_size = tools::get_module_size(nt_base);
        void* function = tools::find_pattern(reinterpret_cast<unsigned char*>(nt_base), nt_size, "48 89 5C 24 ? 55 56 57 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC ? 48 83 65 ? 00 BE ?? ?? ??");
        if (!function)
            return;
        typedef void(__fastcall* MmFreeIndependentPages_t)(void*, std::size_t);
        MmFreeIndependentPages_t page_free = reinterpret_cast<MmFreeIndependentPages_t>(function);
        page_free(base_address, number_of_bytes);
        return;
    }
}