#pragma once

#ifndef _ALLOCATEMEM_H
#define _ALLOCATEMEM_H

inline PVOID allocate_vmm_pool(unsigned __int64 size)
{
    if (size == 0)
    {
        return nullptr; // 失败返回空指针
    }

#pragma warning(suppress:4996)
    return ExAllocatePoolWithTag(NonPagedPool, size, VMM_TAG);
}

inline PVOID allocate_vmm_page_aligned(unsigned __int64 size)
{
    if (size == 0)
    {
        return nullptr;
    }

    size = (size + PAGE_SIZE - 1) & ~(static_cast<unsigned __int64>(PAGE_SIZE) - 1);

    PHYSICAL_ADDRESS highest_address;
    highest_address.QuadPart = MAXULONG64;

    // 多页缓冲确实要求物理连续时使用此分配器。普通池 >= PAGE_SIZE 也保证页对齐，
    // 但不保证跨页物理连续；EPT 各级页表按页登记 PA，可使用普通非分页池。
    return MmAllocateContiguousMemory(size, highest_address);
}

inline void free_vmm_page_aligned(void* pool_address)
{
    if (pool_address != nullptr)
    {
        MmFreeContiguousMemory(pool_address);
    }
}

template <typename T>
inline T allocate_pool(unsigned __int64 size)
{
    return static_cast<T>(allocate_vmm_pool(size));
}

template <typename T>
inline T* allocate_pool()
{
    return static_cast<T*>(allocate_vmm_pool(sizeof(T)));
}

template <typename T>
inline T allocate_page_aligned_pool(unsigned __int64 size)
{
    return static_cast<T>(allocate_vmm_page_aligned(size));
}

template <typename T>
inline T* allocate_page_aligned_pool()
{
    return static_cast<T*>(allocate_vmm_page_aligned(sizeof(T)));
}

template <typename T>
inline T* allocate_contignous_memory()
{
    PHYSICAL_ADDRESS a;
    a.QuadPart = 0ULL - 1;
    return static_cast<T*>(MmAllocateContiguousMemory(sizeof(T), a));
}

template <typename T>
inline T allocate_contignous_memory(unsigned __int64 size)
{
    if (size == 0)
    {
        return nullptr; // 失败返回空指针
    }

    PHYSICAL_ADDRESS a;
    a.QuadPart = 0ULL - 1;
    return static_cast<T>(MmAllocateContiguousMemory(size, a));
}

inline void free_pool(void* pool_address)
{
    if (pool_address)
    {
        ExFreePoolWithTag(pool_address, VMM_TAG);
    }
}

//释放连续内存
inline void free_contignous_memory(void* memory_address)
{
    if (memory_address)
    {
        MmFreeContiguousMemory(memory_address);
    }
}

#endif // !_ALLOCATEMEM_H
