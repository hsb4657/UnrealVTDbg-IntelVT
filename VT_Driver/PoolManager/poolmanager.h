#pragma once

#ifndef _POOL_MANAGER_H
#define _POOL_MANAGER_H

namespace pool_manager
{
    enum allocation_intention
    {
        INTENTION_NONE,
        INTENTION_TRACK_HOOKED_PAGES,
        INTENTION_EXEC_TRAMPOLINE,
        INTENTION_SPLIT_PML2,
        INTENTION_TRACK_HOOKED_FUNCTIONS
    };

    struct __request_new_allocation
    {
        unsigned __int64 size[10];
        unsigned __int32 count[10];
        allocation_intention intention[10];
        volatile LONG state[10]; // 0=free, 1=publishing, 2=ready, 3=allocating
    };

    enum request_slot_state : LONG
    {
        REQUEST_SLOT_FREE = 0,
        REQUEST_SLOT_PUBLISHING = 1,
        REQUEST_SLOT_READY = 2,
        REQUEST_SLOT_ALLOCATING = 3
    };

    struct __pool_table;
    constexpr unsigned pool_hash_count = 256;
    enum pool_state : LONG { POOL_FREE, POOL_BUSY, POOL_DIRTY, POOL_CLEANING };

    struct __pool_manager
    {
        __request_new_allocation* allocation_requests;
        PLIST_ENTRY list_of_allocated_pools;  //已分配池列表
        KSPIN_LOCK lock_for_reading_pool; // Only non-root publication / teardown list.
        void* volatile by_intention[5];
        void* volatile by_address[pool_hash_count];
        volatile long is_request_for_allocation_recived;
        KEVENT refill_event; // 非 root 系统线程的补池唤醒事件
        PETHREAD refill_thread; // 持有对象引用，卸载时可等待线程退出
        volatile long refill_stop;
    };

    struct __pool_table
    {
        void* address;  //缓冲区指针
        unsigned __int64  size;  //缓冲区大小
        allocation_intention intention;  //该内存用于什么
        LIST_ENTRY pool_list;
        volatile LONG state;
        bool recycled; // Owner-only while BUSY; worker publishes before FREE.
        __pool_table* next_intention; // Immutable after publication; never freed while VMX is active.
        __pool_table* next_address;
        unsigned __int64 physical_address;
        bool physically_aligned; //缓冲区使用连续物理内存分配,释放时必须用对应函数
    };

    inline __pool_table* load_pool_head(void* volatile* head)
    {
        return static_cast<__pool_table*>(InterlockedCompareExchangePointer(head, nullptr, nullptr));
    }

    inline unsigned pool_hash(const void* address)
    {
        const auto value = reinterpret_cast<unsigned __int64>(address);
        return static_cast<unsigned>((value >> 4) ^ (value >> 12) ^ (value >> 20)) & (pool_hash_count - 1);
    }

    unsigned __int64 pool_physical_address(const void* base);
    void recycle_released_pools();

    /// <summary>
    /// Writes all information about allocated pools
    /// </summary>
    void dump_pools_info();

    /// <summary>
    /// Request allocation
    /// </summary>
    /// <param name="size">Size of pool</param>
    /// <param name="count">Number of pools to allocate</param>
    /// <param name="intention"></param>
    /// <returns></returns>
    bool request_allocation(unsigned __int64 size, unsigned __int32 count, allocation_intention intention);

    /// <summary>
    /// Initalize pool manager struct and preallocate pools
    /// </summary>
    /// <returns> status </returns>
    bool initialize();

    /// <summary>
    /// Free all allocted pools
    /// </summary>
    void uninitialize();

    /// <summary>
    /// Set information that pool is no longer used by anyone and mark as recycled
    /// </summary>
    /// <param name="address"></param>
    void release_pool(void* address);

    /// <summary>
    /// Allocate all requested pools
    /// </summary>
    /// <returns></returns>
    bool perform_allocation();

    // 当前执行上下文是否处于 VMX root；root 内不得调用阻塞型内存分配。
    bool is_current_context_vmx_root();

    /// <summary>
    /// Returns pre allocated pool and request new one for allocation
    /// </summary>
    /// <param name="intention">Indicates what will be pool used for</param>
    /// <param name="new_pool">If set new pool will (with same properties) be requested to allocate</param>
    /// <param name="size">Only if new_pool is true. Size of new pool</param>
    /// <returns></returns>
	template <typename T>
	T request_pool(allocation_intention intention, bool new_pool, unsigned __int64 size)
	{
        auto* manager = g_vmm_context.pool_manager;
        if (!manager || intention <= INTENTION_NONE || intention > INTENTION_TRACK_HOOKED_FUNCTIONS)
            return (T)nullptr;
        void* address = nullptr;
        bool is_recycled = false;
        auto scan_for_pool = [&]()
        {
            for (auto* entry = load_pool_head(&manager->by_intention[intention]);
                entry; entry = entry->next_intention)
            {
                if (entry->size >= size &&
                    InterlockedCompareExchange(&entry->state, POOL_BUSY, POOL_FREE) == POOL_FREE)
                {
                    address = entry->address;
                    is_recycled = entry->recycled;
                    break;
                }
            }
        };

		scan_for_pool();

		//
		// If pool which we got is recycled then we don't allocate
		// a new one because we don't want to overload memory, If there wasn't any preallocated pool
		// this function will send a request and perform allocation immediately.
		//
		if (new_pool == true &&
			address == nullptr)
		{
			// 仅 PASSIVE 且不在 VMX root 时允许同步补池。VMCALL 在来宾 PASSIVE
			// 发起时，IRQL 仍然是 PASSIVE，但 CPU 已处于 IF=0 的 VMX root；
			// 此时同步分配会让整个物理处理器无法响应时钟中断。
			if (!is_current_context_vmx_root() &&
                KeGetCurrentIrql() == PASSIVE_LEVEL)
			{
				(void)request_allocation(size, 1, intention);
				(void)perform_allocation();
			}
			else
			{
				// root 只登记请求，由 PASSIVE 系统线程在非 root 上下文补池。
				(void)request_allocation(size, 1, intention);
			}
			scan_for_pool();
		}

		//
		// Pre-allocated pools are consumed sequentially.  Keep a queued request behind
		// a newly taken buffer so the next allocation can be served without stalling.
		//
		if (new_pool == true && address != nullptr && is_recycled == false)
		{
			(void)request_allocation(size, 1, intention);
		}

		return (T)address;
	}
}

#endif // !_POOL_MANAGER_H
