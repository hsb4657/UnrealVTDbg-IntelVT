#pragma once

#include <cstddef>
#include <cstdint>

namespace hv::trampoline_policy
{
    // The current trampoline copies instructions verbatim; it has no relocator.
    // Accept only decoded, known position-independent encodings. Unknown encodings
    // must fail installation instead of silently changing a branch/data target.
    inline bool CanCopyVerbatim(const std::uint8_t* bytes, std::size_t length)
    {
        if (!bytes || length == 0 || length > 15) return false;
        std::size_t index = 0;
        while (index < length)
        {
            const auto p = bytes[index];
            if ((p >= 0x40 && p <= 0x4f) || p == 0x66 || p == 0x67 ||
                p == 0xf0 || p == 0xf2 || p == 0xf3 || p == 0x2e ||
                p == 0x36 || p == 0x3e || p == 0x26 || p == 0x64 || p == 0x65)
                ++index;
            else break;
        }
        if (index == length) return false;
        const auto op = bytes[index++];
        // Register push/pop, immediates, accumulator arithmetic and plain returns.
        if ((op >= 0x50 && op <= 0x5f) || (op >= 0xb0 && op <= 0xbf) ||
            (op <= 0x3d && ((op & 7) == 4 || (op & 7) == 5)) ||
            op == 0x68 || op == 0x6a || op == 0x90 || op == 0x98 || op == 0x99 ||
            op == 0x9c || op == 0x9d || op == 0xa8 || op == 0xa9 ||
            op == 0xc2 || op == 0xc3 || op == 0xc9 || op == 0xfc || op == 0xfd)
            return true;

        bool hasModrm = (op <= 0x3b && (op & 7) <= 3) ||
            op == 0x63 || op == 0x69 || op == 0x6b ||
            op == 0x80 || op == 0x81 || op == 0x83 || (op >= 0x84 && op <= 0x8f) ||
            op == 0xc0 || op == 0xc1 || op == 0xc6 || op == 0xc7 ||
            (op >= 0xd0 && op <= 0xd3) || op == 0xf6 || op == 0xf7 || op == 0xfe || op == 0xff;
        if (op == 0x0f)
        {
            if (index == length) return false;
            const auto op2 = bytes[index++];
            hasModrm = op2 == 0x1f || op2 == 0x1e ||
                (op2 >= 0x40 && op2 <= 0x4f) || (op2 >= 0x90 && op2 <= 0x9f) ||
                op2 == 0xaf || op2 == 0xb0 || op2 == 0xb1 || op2 == 0xb6 ||
                op2 == 0xb7 || op2 == 0xbe || op2 == 0xbf || op2 == 0xc0 || op2 == 0xc1;
        }
        if (!hasModrm || index == length) return false;
        const auto modrm = bytes[index];
        if (op == 0x8f && (modrm & 0x38) != 0) return false; // Exclude XOP prefix encodings.
        if (op == 0xc7 && modrm == 0xf8) return false; // XBEGIN has a relative fallback.
        // mod=00,r/m=101 is RIP/EIP-relative even with an address-size override.
        return (modrm & 0xc7) != 0x05;
    }
}
