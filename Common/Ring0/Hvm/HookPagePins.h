#pragma once

// Include after the driver's WDK headers. Initialize before publishing its device;
// ReleaseAll only after all EPT redirects are removed and runtime calls drained.
namespace hv
{
    class HookPagePins
    {
        struct Pin
        {
            LIST_ENTRY link;
            PMDL mdl;
            PFN_NUMBER pfn;
        };
        LIST_ENTRY pins_;
        FAST_MUTEX mutex_;
        static constexpr ULONG tag_ = 'pHvU';

    public:
        void Initialize()
        {
            InitializeListHead(&pins_);
            ExInitializeFastMutex(&mutex_);
        }

        bool Acquire(void* target)
        {
            if (!target || KeGetCurrentIrql() > APC_LEVEL) return false;
#pragma warning(suppress:4996)
            auto* pin = static_cast<Pin*>(ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(Pin), tag_));
            if (!pin) return false;
            pin->mdl = IoAllocateMdl(PAGE_ALIGN(target), PAGE_SIZE, FALSE, FALSE, nullptr);
            if (!pin->mdl) { ExFreePoolWithTag(pin, tag_); return false; }
            __try
            {
                MmProbeAndLockPages(pin->mdl, KernelMode, IoReadAccess);
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                IoFreeMdl(pin->mdl);
                ExFreePoolWithTag(pin, tag_);
                return false;
            }
            pin->pfn = MmGetMdlPfnArray(pin->mdl)[0];
            bool duplicate = false;
            ExAcquireFastMutex(&mutex_);
            for (auto* item = pins_.Flink; item != &pins_; item = item->Flink)
            {
                if (CONTAINING_RECORD(item, Pin, link)->pfn == pin->pfn)
                { duplicate = true; break; }
            }
            if (!duplicate) InsertTailList(&pins_, &pin->link);
            ExReleaseFastMutex(&mutex_);
            if (duplicate)
            {
                MmUnlockPages(pin->mdl);
                IoFreeMdl(pin->mdl);
                ExFreePoolWithTag(pin, tag_);
            }
            return true;
        }

        void ReleaseAll()
        {
            for (;;)
            {
                ExAcquireFastMutex(&mutex_);
                auto* link = IsListEmpty(&pins_) ? nullptr : RemoveHeadList(&pins_);
                ExReleaseFastMutex(&mutex_);
                if (!link) return;
                auto* pin = CONTAINING_RECORD(link, Pin, link);
                MmUnlockPages(pin->mdl);
                IoFreeMdl(pin->mdl);
                ExFreePoolWithTag(pin, tag_);
            }
        }
    };
}
