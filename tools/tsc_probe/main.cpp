// TSC 探针：用来判断"这台机器现在有没有 hypervisor 在偷时间"。
//
// 用法（管理员或普通用户都行，不需要驱动）：
//   cl /O2 /EHsc tsc_probe.cpp
//   tsc_probe.exe [每项采样次数，默认 200000]
//
// 判定逻辑（三条互相独立的证据）：
//   1) RDTSC 环回      —— 两条相邻 RDTSC 的差值。裸机一般 20~60 cycle（含乱序影响）。
//   2) RDTSCP 环回     —— 同上，用 RDTSCP 再测一遍。若 RDTSC 被拦截而 RDTSCP 没有，
//                         两者会差出数量级，这是最干净的"是否虚拟化"判据。
//   3) CPUID 包裹开销  —— rdtsc;cpuid;rdtsc 的差值。裸机 CPUID 约 100~300 cycle；
//                         如果这里稳定上千，说明这条指令被 VM-exit 接管了。
//
// 对比方法：先在 VT 驱动未加载时跑一遍记下基线，再加载 VT 驱动跑一遍，
// 两组数字接近 => 时间戳对冲生效；CPUIP 那一项暴涨 => 对冲没生效或没扣到位。

#include <windows.h>
#include <intrin.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <vector>

namespace
{
	struct stats
	{
		unsigned __int64 min = ~0ull;
		unsigned __int64 median = 0;
		unsigned __int64 max = 0;
		double average = 0.0;
	};

	stats summarize(std::vector<unsigned __int64>& samples)
	{
		stats result;
		if (samples.empty())
		{
			return result;
		}

		std::sort(samples.begin(), samples.end());
		result.min = samples.front();
		result.median = samples[samples.size() / 2];
		result.max = samples.back();

		unsigned __int64 total = 0;
		for (unsigned __int64 value : samples)
		{
			total += value;
		}
		result.average = static_cast<double>(total) / static_cast<double>(samples.size());
		return result;
	}

	void print(const char* title, const stats& value)
	{
		std::printf("%-28s min=%5llu  median=%6llu  avg=%8.1f  max=%6llu\n",
			title, value.min, value.median, value.average, value.max);
	}

	// 两条相邻 RDTSC 的差值
	stats probe_rdtsc(unsigned int count)
	{
		std::vector<unsigned __int64> samples;
		samples.reserve(count);
		for (unsigned int index = 0; index < count; ++index)
		{
			unsigned __int64 const start = __rdtsc();
			unsigned __int64 const end = __rdtsc();
			samples.push_back(end - start);
		}
		return summarize(samples);
	}

	// 两条相邻 RDTSCP 的差值
	stats probe_rdtscp(unsigned int count)
	{
		std::vector<unsigned __int64> samples;
		samples.reserve(count);
		for (unsigned int index = 0; index < count; ++index)
		{
			unsigned int aux1 = 0;
			unsigned int aux2 = 0;
			unsigned __int64 const start = __rdtscp(&aux1);
			unsigned __int64 const end = __rdtscp(&aux2);
			samples.push_back(end - start);
		}
		return summarize(samples);
	}

	// rdtsc -> cpuid -> rdtsc：最经典的虚拟化耗时探针
	stats probe_cpuid(unsigned int count)
	{
		std::vector<unsigned __int64> samples;
		samples.reserve(count);
		int registers[4] = {};
		for (unsigned int index = 0; index < count; ++index)
		{
			unsigned __int64 const start = __rdtsc();
			__cpuidex(registers, 0, 0);
			unsigned __int64 const end = __rdtsc();
			samples.push_back(end - start);
		}
		return summarize(samples);
	}
}

int main(int argc, char** argv)
{
	unsigned int count = 200000;
	if (argc > 1)
	{
		count = static_cast<unsigned int>(std::strtoul(argv[1], nullptr, 10));
		if (count < 1000)
		{
			count = 1000;
		}
	}

	int registers[4] = {};
	__cpuidex(registers, 0, 0);
	std::printf("CPU vendor: %.12s\n", reinterpret_cast<const char*>(&registers[1]));
	std::printf("采样次数: %u（每项独立采样）\n\n", count);

	stats const rdtsc_round = probe_rdtsc(count);
	stats const rdtscp_round = probe_rdtscp(count);
	stats const cpuid_wrap = probe_cpuid(count);

	print("RDTSC  round-trip", rdtsc_round);
	print("RDTSCP round-trip", rdtscp_round);
	print("CPUID  wrapped", cpuid_wrap);

	std::printf("\n--- 判读 ---\n");
	if (cpuid_wrap.median > 1000)
	{
		std::printf("[!] CPUID 被接管：中位数 %llu cycle，远超裸机 100~300 的水平。\n", cpuid_wrap.median);
		std::printf("    => 要么没有加载 VT 驱动（正常），要么对冲没生效（异常）。\n");
	}
	else
	{
		std::printf("[ok] CPUID 包裹开销 %llu cycle，处于裸机量级：这条时间通道已经对干净了。\n", cpuid_wrap.median);
	}

	unsigned __int64 const lower = rdtsc_round.median < rdtscp_round.median ? rdtsc_round.median : rdtscp_round.median;
	unsigned __int64 const higher = rdtsc_round.median < rdtscp_round.median ? rdtscp_round.median : rdtsc_round.median;
	if (lower != 0 && higher > lower * 8)
	{
		std::printf("[!] RDTSC 与 RDTSCP 差出 8 倍以上（%llu vs %llu）：两条时间通道被区别对待，\n", lower, higher);
		std::printf("    这是比 CPUID 更致命的特征，说明其中一条指令仍然直通物理 TSC。\n");
	}
	else
	{
		std::printf("[ok] RDTSC 与 RDTSCP 量级一致（%llu vs %llu）：没有出现时间通道分裂。\n", rdtsc_round.median, rdtscp_round.median);
	}

	std::printf("\n提示：先在 VT 驱动未加载时跑一遍做基线，加载后再跑一遍对比。\n");
	return 0;
}
