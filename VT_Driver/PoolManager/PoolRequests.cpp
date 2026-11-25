#include "PoolManagerInternal.h"

namespace pool_manager
{
    bool is_current_context_vmx_root()
    {
        if (g_vmm_context.vcpu == nullptr ||
            g_vmm_context.processor_count == 0)
        {
            return false;
        }

        const unsigned __int64 begin =
            reinterpret_cast<unsigned __int64>(g_vmm_context.vcpu);
        const unsigned __int64 size =
            static_cast<unsigned __int64>(sizeof(__vcpu)) *
            g_vmm_context.processor_count;
        const unsigned __int64 candidate = _readfsbase_u64();
        if (candidate < begin ||
            candidate - begin >= size ||
            (candidate - begin) % sizeof(__vcpu) != 0)
        {
            return false;
        }

        return reinterpret_cast<__vcpu*>(candidate)
            ->vmexit_info.vmx_root_active != 0;
    }

    /// <param name="size">Size of pool</param>
    /// <param name="count">Number of pools to allocate</param>
    /// <param name="intention"></param>
    /// <returns></returns>
    /// <summary>
    /// Request allocation
    /// </summary>
    bool request_allocation(unsigned __int64 size, unsigned __int32 count, allocation_intention intention)
    {
        if (g_vmm_context.pool_manager == nullptr ||
            g_vmm_context.pool_manager->allocation_requests == nullptr)
        {
            LogError("Pool manager is not initialized");
            return false;
        }

        if (size == 0 || count == 0)
        {
            LogError("Invalid pool allocation request");
            return false;
        }

        bool request_queued = false;
        for (unsigned __int64 i = 0; i < 10; i++)
        {
            if (InterlockedCompareExchange(
                &g_vmm_context.pool_manager->allocation_requests->state[i],
                REQUEST_SLOT_PUBLISHING,
                REQUEST_SLOT_FREE) == REQUEST_SLOT_FREE)
            {
                g_vmm_context.pool_manager->allocation_requests->count[i] = count;
                g_vmm_context.pool_manager->allocation_requests->size[i] = size;
                g_vmm_context.pool_manager->allocation_requests->intention[i] = intention;
                KeMemoryBarrier();
                InterlockedExchange(
                    &g_vmm_context.pool_manager->allocation_requests->state[i],
                    REQUEST_SLOT_READY);
                InterlockedExchange(
                    &g_vmm_context.pool_manager->is_request_for_allocation_recived,
                    1);
                request_queued = true;
                break;
            }
        }

        // VMX root 内只做原子登记；系统线程会用超时轮询发现 root 提交的请求。
        if (request_queued &&
            !is_current_context_vmx_root() &&
            KeGetCurrentIrql() <= DISPATCH_LEVEL)
        {
            KeSetEvent(
                &g_vmm_context.pool_manager->refill_event,
                IO_NO_INCREMENT,
                FALSE);
        }
        return request_queued;
    }

    /// <summary>
    /// Set information that pool is no longer used anymore
    /// </summary>
    /// <param name="address"></param>
    void release_pool(void* address)
    {
        if (address == nullptr ||
            g_vmm_context.pool_manager == nullptr ||
            g_vmm_context.pool_manager->list_of_allocated_pools == nullptr)
        {
            return;
        }

        auto* manager = g_vmm_context.pool_manager;
        for (auto* node = load_pool_head(&manager->by_address[pool_hash(address)]);
            node; node = node->next_address)
        {
            if (node->address != address) continue;
            // No Windows lock, memory clearing, or event signaling in VMX root.
            // The caller must unlink the object and invalidate EPT before retiring it.
            InterlockedCompareExchange(&node->state, POOL_DIRTY, POOL_BUSY);
            return;
        }
    }

    unsigned __int64 pool_physical_address(const void* base)
    {
        auto* manager = g_vmm_context.pool_manager;
        if (!manager) return 0;
        for (auto* node = load_pool_head(&manager->by_address[pool_hash(base)]);
            node; node = node->next_address)
            if (node->address == base) return node->physical_address;
        return 0;
    }

    void recycle_released_pools()
    {
        auto* manager = g_vmm_context.pool_manager;
        if (!manager || is_current_context_vmx_root() || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;
        for (unsigned i = 1; i <= INTENTION_TRACK_HOOKED_FUNCTIONS; ++i)
        {
            for (auto* node = load_pool_head(&manager->by_intention[i]);
                node; node = node->next_intention)
            {
                if (InterlockedCompareExchange(&node->state, POOL_CLEANING, POOL_DIRTY) != POOL_DIRTY)
                    continue;
                RtlSecureZeroMemory(node->address, node->size);
                node->recycled = true;
                InterlockedExchange(&node->state, POOL_FREE);
            }
        }
    }
}
