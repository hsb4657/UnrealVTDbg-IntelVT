#pragma once
#include "../Driver.h"
#include "../poolmanager.h"
#include "../Globals.h"
#include "../mtrr.h"
#include "../EPT.h"
#include "../Ept/EptCommon.h"
#include "../vmexit_handler.h"
#include "../hypervisor_routines.h"
#include "../Vmcs/VmcsApi.h"
#include "../interrupt.h"
#include "../AsmCallset.h"
#include "../crx.h"
#include "../drx.h"
#include "../cpuid.h"
#include "../msr.h"
#include "../invalid_vpid.h"
#include "../invalid_pcid.h"
#include "../segment.h"
#include "VmxFatal.h"

// 通用辅助函数
// 恢复来宾状态
void RestoreGuest(); // 将来宾寄存器状态恢复到继续执行
bool PrepareGuestForVmxoff(__vcpu* vcpu); // 受检采集并恢复Guest状态，同时生成汇编使用的VMXOFF恢复帧
void set_hide_vm_exit_overhead(__vcpu* vcpu, bool value);
void hide_vm_exit_overhead(__vcpu* vcpu); // 已废弃：时间开销对账改由 account_vm_exit_overhead() 统一处理，保留声明仅为兼容
// 统一时间源：guest 侧所有 TSC 读取（RDTSC/RDTSCP/RDMSR(IA32_TSC)）都必须走这里。
// 原理：返回「本 exit 入口 TSC + 全局累计偏移」，硬件 VM-exit/VM-entry 延迟是常量会在差值里抵消，
//       而 handler 自身耗时（CPUID/MSR 模拟、伪页切换）正好被偏移扣掉。
// 作用：让 guest 在 rdtsc 前后包一条被拦截的指令时，读到的差值等于裸机同款开销。
// 结果：单调不回退的 64 位时间戳。
unsigned __int64 guest_visible_tsc(__vcpu* vcpu);
// 每次时间敏感 VM-exit 结束时调用：把本核在 root 里消耗的 TSC 时间从全局偏移中扣除。
// 原理：只有共享的全局偏移才能同时满足"隐藏开销"与"跨核时间一致"两个约束。
// 参数2：本次 exit 的入口 TSC（即 vmexit_handler 里的 telemetryStartTsc）。
void account_vm_exit_overhead(__vcpu* vcpu, unsigned __int64 exit_start_tsc);
void skip_instruction(); // 直接跳过当前指令
// 调整 RIP 指向下一条指令
void adjust_rip(__vcpu* vcpu); // 更新来宾 RIP，跳过已执行指令
void CleanUp(__vcpu* vcpu, __ept_hooked_page_info* hooked_page_info);
