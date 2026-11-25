#include "PoolManagerInternal.h"

namespace pool_manager
{
    inline const char* intention_to_string(allocation_intention intention)
    {
        switch (intention)
        {
        case INTENTION_NONE:   return "None";
        case INTENTION_TRACK_HOOKED_PAGES:   return "Track Hooked Pages";
        case INTENTION_EXEC_TRAMPOLINE: return "Trampoline";
        case INTENTION_SPLIT_PML2: return "Split Pml2";
        case INTENTION_TRACK_HOOKED_FUNCTIONS: return "Trace Hooked Functions";
        default:      return "Unknown";
        }
    }

    /// <summary>
    /// Writes all information about allocated pools
    /// </summary>
    void dump_pools_info()
    {
        auto* manager = g_vmm_context.pool_manager;
        if (!manager) return;
        for (unsigned i = 1; i <= INTENTION_TRACK_HOOKED_FUNCTIONS; ++i)
            for (auto* node = load_pool_head(&manager->by_intention[i]); node; node = node->next_intention)
                LogDump("Pool: %p Size: %llu Intention: %s State: %ld",
                    node->address, node->size, intention_to_string(node->intention),
                    InterlockedCompareExchange(&node->state, 0, 0));
    }
}
