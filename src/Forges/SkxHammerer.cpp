#include "Forges/SkxHammerer.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <unordered_map>
#include <vector>

#define SKXHAMDBG(fmt, ...) fprintf(stderr, "[SkxHammerer] " fmt "\n", ##__VA_ARGS__)

static inline void clflush_one(const void *p) {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("clflush (%0)" :: "r"(p) : "memory");
#else
    (void)p;
#endif
}

static void fill_pattern(volatile char *buf, size_t bytes, unsigned char value) {
    for (size_t i = 0; i < bytes; i++) {
        buf[i] = (char)value;
    }
}

static void flush_buffer(volatile char *buf, size_t bytes) {
    for (size_t i = 0; i < bytes; i += 64) {
        clflush_one((const void *)(buf + i));
    }
    __asm__ __volatile__("mfence" ::: "memory");
}

SkxHammerer::SkxHammerer() {
    SKXHAMDBG("constructor");
}

std::vector<SKXHit> SkxHammerer::filter_to_bank(const std::vector<SKXHit> &hits, int target_bank) {
    std::vector<SKXHit> out;
    for (const auto &hit : hits) {
        if (hit.bank_id == target_bank) {
            out.push_back(hit);
        }
    }

    SKXHAMDBG("filter_to_bank: target_bank=%d input=%zu output=%zu",
              target_bank, hits.size(), out.size());
    return out;
}

std::vector<SKXHit> SkxHammerer::filter_to_common_context(const std::vector<SKXHit> &hits) {
    std::vector<SKXHit> out;
    if (hits.empty()) {
        SKXHAMDBG("filter_to_common_context: empty input");
        return out;
    }

    std::unordered_map<uint64_t, size_t> counts;
    uint64_t best_key = 0;
    size_t best_count = 0;

    for (const auto &hit : hits) {
        const uint64_t key = SKXDecoder::ctx_key(hit);
        const size_t count = ++counts[key];
        if (count > best_count) {
            best_count = count;
            best_key = key;
        }
    }

    for (const auto &hit : hits) {
        if (SKXDecoder::ctx_key(hit) == best_key) {
            out.push_back(hit);
        }
    }

    SKXHAMDBG("filter_to_common_context: input=%zu output=%zu best_count=%zu",
              hits.size(), out.size(), best_count);

    if (!out.empty()) {
        const auto &h = out.front();
        fprintf(stderr,
                "[SkxHammerer] dominant context: socket=%d imc=%d ch=%d dimm=%d rank=%d\n",
                h.socket, h.imc, h.channel, h.dimm, h.rank);
    }

    return out;
}

void SkxHammerer::print_bank_histogram(const std::vector<SKXHit> &hits) {
    std::array<size_t, 16> counts{};
    counts.fill(0);

    for (const auto &hit : hits) {
        if (hit.bank_id >= 0 && hit.bank_id < 16) {
            counts[(size_t)hit.bank_id]++;
        }
    }

    fprintf(stderr, "\n[SkxHammerer] bank histogram:\n");
    for (int i = 0; i < 16; i++) {
        fprintf(stderr, "  bank %2d : %zu hits\n", i, counts[(size_t)i]);
    }
    fprintf(stderr, "\n");
}

int SkxHammerer::choose_best_bank(const std::vector<SKXHit> &hits, int requested_bank) {
    std::array<size_t, 16> counts{};
    counts.fill(0);

    for (const auto &hit : hits) {
        if (hit.bank_id >= 0 && hit.bank_id < 16) {
            counts[(size_t)hit.bank_id]++;
        }
    }

    if (requested_bank >= 0 && requested_bank < 16 && counts[(size_t)requested_bank] > 0) {
        SKXHAMDBG("choose_best_bank: requested bank %d has %zu hits, using it",
                  requested_bank, counts[(size_t)requested_bank]);
        return requested_bank;
    }

    int best_bank = -1;
    size_t best_count = 0;

    for (int i = 0; i < 16; i++) {
        if (counts[(size_t)i] > best_count) {
            best_count = counts[(size_t)i];
            best_bank = i;
        }
    }

    if (best_bank >= 0) {
        SKXHAMDBG("choose_best_bank: requested bank %d unavailable, using best bank %d with %zu hits",
                  requested_bank, best_bank, best_count);
    } else {
        SKXHAMDBG("choose_best_bank: no usable banks found");
    }

    return best_bank;
}

bool SkxHammerer::pick_two_distinct_rows(const std::vector<SKXHit> &hits,
                                         size_t &left_idx,
                                         size_t &right_idx) {
    if (hits.size() < 2) {
        SKXHAMDBG("pick_two_distinct_rows: fewer than 2 hits");
        return false;
    }

    for (size_t i = 0; i < hits.size(); i++) {
        for (size_t j = i + 1; j < hits.size(); j++) {
            if (hits[i].row != hits[j].row) {
                left_idx = i;
                right_idx = j;

                fprintf(stderr,
                        "[SkxHammerer] pick_two_distinct_rows: chose row 0x%llx and row 0x%llx\n",
                        (unsigned long long)hits[i].row,
                        (unsigned long long)hits[j].row);
                return true;
            }
        }
    }

    SKXHAMDBG("pick_two_distinct_rows: all hits are on the same row");
    return false;
}

void SkxHammerer::hammer_pair(volatile char *a, volatile char *b, size_t iters) {
    SKXHAMDBG("hammer_pair: start a=%p b=%p iters=%zu", (void *)a, (void *)b, iters);

    volatile unsigned char sink = 0;

    for (size_t i = 0; i < iters; i++) {
        clflush_one((const void *)a);
        clflush_one((const void *)b);
        __asm__ __volatile__("mfence" ::: "memory");
        sink ^= *a;
        sink ^= *b;

        if ((i % 100000) == 0) {
            fprintf(stderr,
                    "[SkxHammerer] hammer_pair progress: i=%zu / %zu\n",
                    i, iters);
        }
    }

    if (sink == 0xFF) {
        fprintf(stderr, "[SkxHammerer] sink guard triggered\n");
    }

    SKXHAMDBG("hammer_pair: done");
}

bool SkxHammerer::run(size_t bytes,
                      size_t step,
                      size_t max_hits,
                      int target_bank,
                      size_t hammer_iters) {
    SKXHAMDBG("run: bytes=%zu step=%zu max_hits=%zu target_bank=%d hammer_iters=%zu",
              bytes, step, max_hits, target_bank, hammer_iters);

    if (!decoder_.init()) {
        SKXHAMDBG("run: decoder init failed");
        return false;
    }

    volatile char *buf = (volatile char *)mmap(nullptr,
                                               bytes,
                                               PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS,
                                               -1,
                                               0);
    if (buf == MAP_FAILED) {
        perror("[SkxHammerer] mmap failed");
        return false;
    }

    SKXHAMDBG("allocated buffer at %p", (void *)buf);

    /*
     * Fill with a fixed pattern so flips are easy to detect.
     * 0xFF is common for Rowhammer experiments, since 1->0 flips are easy to spot.
     */
    fill_pattern(buf, bytes, 0xFF);
    flush_buffer(buf, bytes);
    SKXHAMDBG("buffer filled with 0xFF pattern");

    /*
     * Save a baseline copy for post-hammer comparison.
     */
    std::vector<unsigned char> baseline(bytes);
    for (size_t i = 0; i < bytes; i++) {
        baseline[i] = (unsigned char)buf[i];
    }
    SKXHAMDBG("baseline snapshot captured");

    auto hits = decoder_.collect_hits(buf, bytes, step, max_hits);
    SKXHAMDBG("decoder returned %zu hits", hits.size());

    if (hits.empty()) {
        SKXHAMDBG("no decoded hits returned");
        munmap((void *)buf, bytes);
        return false;
    }

    print_bank_histogram(hits);

    const int chosen_bank = choose_best_bank(hits, target_bank);
    if (chosen_bank < 0) {
        SKXHAMDBG("no bank available for hammering");
        munmap((void *)buf, bytes);
        return false;
    }

    fprintf(stderr,
            "[SkxHammerer] requested bank=%d, chosen bank=%d\n",
            target_bank, chosen_bank);

    auto bank_hits = filter_to_bank(hits, chosen_bank);
    auto context_hits = filter_to_common_context(bank_hits);

    if (context_hits.size() < 2) {
        SKXHAMDBG("not enough hits in chosen bank/context to hammer");
        munmap((void *)buf, bytes);
        return false;
    }

    std::sort(context_hits.begin(), context_hits.end(), [](const SKXHit &a, const SKXHit &b) {
        if (a.row != b.row) return a.row < b.row;
        if (a.col != b.col) return a.col < b.col;
        if (a.imc != b.imc) return a.imc < b.imc;
        if (a.channel != b.channel) return a.channel < b.channel;
        return a.va < b.va;
    });

    SKXHAMDBG("sorted %zu context hits by row/col/imc/ch", context_hits.size());

    size_t left = 0;
    size_t right = 0;
    if (!pick_two_distinct_rows(context_hits, left, right)) {
        SKXHAMDBG("could not find two distinct rows in same bank/context");
        munmap((void *)buf, bytes);
        return false;
    }

    fprintf(stderr,
            "[SkxHammerer] chosen pair:\n"
            "  A: socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=0x%llx col=0x%llx va=%p pa=0x%llx\n"
            "  B: socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=0x%llx col=0x%llx va=%p pa=0x%llx\n",
            context_hits[left].socket,
            context_hits[left].imc,
            context_hits[left].channel,
            context_hits[left].dimm,
            context_hits[left].rank,
            context_hits[left].bank_group,
            context_hits[left].bank,
            context_hits[left].bank_id,
            (unsigned long long)context_hits[left].row,
            (unsigned long long)context_hits[left].col,
            (void *)context_hits[left].va,
            (unsigned long long)context_hits[left].pa,

            context_hits[right].socket,
            context_hits[right].imc,
            context_hits[right].channel,
            context_hits[right].dimm,
            context_hits[right].rank,
            context_hits[right].bank_group,
            context_hits[right].bank,
            context_hits[right].bank_id,
            (unsigned long long)context_hits[right].row,
            (unsigned long long)context_hits[right].col,
            (void *)context_hits[right].va,
            (unsigned long long)context_hits[right].pa);

    hammer_pair(context_hits[left].va, context_hits[right].va, hammer_iters);

    /*
     * Force data back from memory hierarchy before scan.
     */
    flush_buffer(buf, bytes);
    SKXHAMDBG("post-hammer flush complete");

    /*
     * Compare post-hammer contents against baseline.
     */
    size_t flip_count = 0;
    const size_t max_report = 64;

    fprintf(stderr, "\n[SkxHammerer] scanning for flips...\n");

    for (size_t i = 0; i < bytes; i++) {
        unsigned char now = (unsigned char)buf[i];
        unsigned char was = baseline[i];

        if (now != was) {
            if (flip_count < max_report) {
                fprintf(stderr,
                        "[SkxHammerer] FLIP offset=0x%zx addr=%p before=0x%02x after=0x%02x\n",
                        i, (void *)(buf + i), was, now);
            }
            flip_count++;
        }
    }

    if (flip_count == 0) {
        fprintf(stderr, "[SkxHammerer] RESULT: no flips detected\n");
    } else {
        fprintf(stderr,
                "[SkxHammerer] RESULT: %zu flips detected%s\n",
                flip_count,
                (flip_count > max_report ? " (first 64 shown)" : ""));
    }

    munmap((void *)buf, bytes);
    SKXHAMDBG("run: complete");
    return true;
}
