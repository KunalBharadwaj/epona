#pragma once
//
// Classic `hexdump -C` style output. Milestone 0's proof of life: dump every
// frame the kernel hands us so we can eyeball raw packets before we parse them.
//
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>

namespace net {

inline void hexdump(std::span<const std::byte> data, std::FILE* out = stdout) {
    const std::size_t n = data.size();
    for (std::size_t i = 0; i < n; i += 16) {
        std::fprintf(out, "%08zx  ", i);

        // Hex columns, split into two groups of 8 with a gap.
        for (std::size_t j = 0; j < 16; ++j) {
            if (i + j < n) {
                std::fprintf(out, "%02x ",
                             std::to_integer<unsigned>(data[i + j]));
            } else {
                std::fprintf(out, "   ");
            }
            if (j == 7) std::fputc(' ', out);
        }

        // ASCII gutter.
        std::fputc(' ', out);
        std::fputc('|', out);
        for (std::size_t j = 0; j < 16 && i + j < n; ++j) {
            auto c = std::to_integer<unsigned char>(data[i + j]);
            std::fputc((c >= 0x20 && c < 0x7f) ? static_cast<int>(c) : '.', out);
        }
        std::fputc('|', out);
        std::fputc('\n', out);
    }
    std::fprintf(out, "          (%zu bytes)\n", n);
}

} // namespace net
