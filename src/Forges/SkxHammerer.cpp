#include "Forges/SkxHammerer.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
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

std::vector<SKXPairCandidate> SkxHammerer::build_candidate_pairs(const std::vector<SKXHit> &hits,
                                                                 size_t max_pairs) {
    std::vector<SKXPairCandidate> out;
    if (hits.size() < 2) {
        SKXHAMDBG("build_candidate_pairs: not enough hits");
        return out;
    }

    /*
     * Assumes caller already filtered to a single bank and a single dominant context.
     * We now want row-distinct pairs, with preference for small row distance.
     */
    for (size_t i = 0; i < hits.size(); i++) {
        for (size_t j = i + 1; j < hits.size(); j++) {
            if (hits[i].row == hits[j].row) continue;

            SKXPairCandidate cand{};
            cand.a = hits[i];
            cand.b = hits[j];
            cand.row_distance = (long)hits[j].row - (long)hits[i].row;
            if (cand.row_distance < 0) cand.row_distance = -cand.row_distance;

            out.push_back(cand);
        }
    }

    std::sort(out.begin(), out.end(), [](const SKXPairCandidate &x, const SKXPairCandidate &y) {
        if (x.row_distance != y.row_distance) return x.row_distance < y.row_distance;
        if (x.a.row != y.a.row) return x.a.row < y.a.row;
        if (x.b.row != y.b.row) return x.b.row < y.b.row;
        return x.a.va < y.a.va;
    });

    /*
     * Keep only one pair per row-row combination to avoid too many duplicates
     * across different columns of the same two rows.
     */
    std::vector<SKXPairCandidate> deduped;
    deduped.reserve(out.size());

    std::unordered_map<uint64_t, bool> seen;
    for (const auto &cand : out) {
        uint64_t r1 = cand.a.row;
        uint64_t r2 = cand.b.row;
        if (r1 > r2) std::swap(r1, r2);

        uint64_t key = (r1 << 32) ^ r2;
        if (seen.find(key) != seen.end()) continue;
        seen[key] = true;

        deduped.push_back(cand);
        if (deduped.size() >= max_pairs) break;
    }

    SKXHAMDBG("build_candidate_pairs: raw=%zu deduped=%zu",
              out.size(), deduped.size());
    return deduped;
}

void SkxHammerer::print_candidate_pairs(const std::vector<SKXPairCandidate> &pairs, size_t max_to_print) {
    fprintf(stderr, "\n[SkxHammerer] candidate pairs (showing up to %zu):\n", max_to_print);

    const size_t n = std::min(max_to_print, pairs.size());
    for (size_t i = 0; i < n; i++) {
        const auto &p = pairs[i];
        fprintf(stderr,
                "  #%zu rowA=0x%llx rowB=0x%llx distance=%ld bank_id=%d "
                "A_va=%p B_va=%p\n",
                i,
                (unsigned long long)p.a.row,
                (unsigned long long)p.b.row,
                p.row_distance,
                p.a.bank_id,
                (void *)p.a.va,
                (void *)p.b.va);
    }
    fprintf(stderr, "\n");
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

        if ((i % 1000000) == 0) {
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

size_t SkxHammerer::scan_flips(volatile char *buf,
                               size_t bytes,
                               const std::vector<unsigned char> &baseline,
                               size_t max_report) {
    size_t flip_count = 0;

    for (size_t i = 0; i < bytes; i++) {
        const unsigned char now = (unsigned char)buf[i];
        const unsigned char was = baseline[i];

        if (now != was) {
            if (flip_count < max_report) {
                fprintf(stderr,
                        "[SkxHammerer] FLIP offset=0x%zx addr=%p before=0x%02x after=0x%02x\n",
                        i, (void *)(buf + i), was, now);
            }
            flip_count++;
        }
    }

    return flip_count;
}

bool SkxHammerer::write_csv_report(const std::string &path,
                                   const std::vector<SKXPairResult> &results) {
    FILE *fp = fopen(path.c_str(), "w");
    if (!fp) {
        perror("[SkxHammerer] fopen(csv report) failed");
        return false;
    }

    fprintf(fp,
            "pair_index,hammer_iters,flip_count,row_distance,"
            "socket,imc,channel,dimm,rank,bank_group,bank,bank_id,"
            "row_a,col_a,va_a,pa_a,row_b,col_b,va_b,pa_b\n");

    for (size_t i = 0; i < results.size(); i++) {
        const auto &r = results[i];
        fprintf(fp,
                "%zu,%zu,%zu,%ld,"
                "%d,%d,%d,%d,%d,%d,%d,%d,"
                "%llu,%llu,%p,0x%llx,%llu,%llu,%p,0x%llx\n",
                i,
                r.hammer_iters,
                r.flip_count,
                r.pair.row_distance,

                r.pair.a.socket,
                r.pair.a.imc,
                r.pair.a.channel,
                r.pair.a.dimm,
                r.pair.a.rank,
                r.pair.a.bank_group,
                r.pair.a.bank,
                r.pair.a.bank_id,

                (unsigned long long)r.pair.a.row,
                (unsigned long long)r.pair.a.col,
                (void *)r.pair.a.va,
                (unsigned long long)r.pair.a.pa,

                (unsigned long long)r.pair.b.row,
                (unsigned long long)r.pair.b.col,
                (void *)r.pair.b.va,
                (unsigned long long)r.pair.b.pa);
    }

    fclose(fp);
    fprintf(stderr, "[SkxHammerer] wrote CSV report to %s\n", path.c_str());
    return true;
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

    fill_pattern(buf, bytes, 0xFF);
    flush_buffer(buf, bytes);
    SKXHAMDBG("buffer filled with 0xFF pattern");

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
        SKXHAMDBG("not enough hits in chosen bank/context to continue");
        munmap((void *)buf, bytes);
        return false;
    }

    std::sort(context_hits.begin(), context_hits.end(), [](const SKXHit &a, const SKXHit &b) {
        if (a.row != b.row) return a.row < b.row;
        if (a.col != b.col) return a.col < b.col;
        return a.va < b.va;
    });

    SKXHAMDBG("sorted %zu context hits by row/col", context_hits.size());

    const size_t max_pairs = 16;
    auto pairs = build_candidate_pairs(context_hits, max_pairs);

    if (pairs.empty()) {
        SKXHAMDBG("no candidate pairs found");
        munmap((void *)buf, bytes);
        return false;
    }

    print_candidate_pairs(pairs, 16);

    std::vector<SKXPairResult> results;
    results.reserve(pairs.size());

    size_t best_flip_count = 0;
    long best_distance = std::numeric_limits<long>::max();
    ssize_t best_index = -1;

    for (size_t idx = 0; idx < pairs.size(); idx++) {
        const auto &pair = pairs[idx];

        fprintf(stderr,
                "\n[SkxHammerer] === TESTING PAIR %zu/%zu ===\n"
                "  rowA=0x%llx rowB=0x%llx distance=%ld bank_id=%d\n",
                idx + 1,
                pairs.size(),
                (unsigned long long)pair.a.row,
                (unsigned long long)pair.b.row,
                pair.row_distance,
                pair.a.bank_id);

        /*
         * Reset memory before each trial.
         */
        fill_pattern(buf, bytes, 0xFF);
        flush_buffer(buf, bytes);

        std::vector<unsigned char> baseline(bytes);
        for (size_t i = 0; i < bytes; i++) {
            baseline[i] = (unsigned char)buf[i];
        }

        fprintf(stderr,
                "[SkxHammerer] pair %zu addresses:\n"
                "  A: socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=0x%llx col=0x%llx va=%p pa=0x%llx\n"
                "  B: socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=0x%llx col=0x%llx va=%p pa=0x%llx\n",
                idx,
                pair.a.socket, pair.a.imc, pair.a.channel, pair.a.dimm, pair.a.rank,
                pair.a.bank_group, pair.a.bank, pair.a.bank_id,
                (unsigned long long)pair.a.row,
                (unsigned long long)pair.a.col,
                (void *)pair.a.va,
                (unsigned long long)pair.a.pa,

                pair.b.socket, pair.b.imc, pair.b.channel, pair.b.dimm, pair.b.rank,
                pair.b.bank_group, pair.b.bank, pair.b.bank_id,
                (unsigned long long)pair.b.row,
                (unsigned long long)pair.b.col,
                (void *)pair.b.va,
                (unsigned long long)pair.b.pa);

        hammer_pair(pair.a.va, pair.b.va, hammer_iters);

        flush_buffer(buf, bytes);
        fprintf(stderr, "[SkxHammerer] post-hammer flush complete for pair %zu\n", idx);

        fprintf(stderr, "[SkxHammerer] scanning for flips for pair %zu...\n", idx);
        const size_t flip_count = scan_flips(buf, bytes, baseline, 16);

        if (flip_count == 0) {
            fprintf(stderr, "[SkxHammerer] pair %zu RESULT: no flips detected\n", idx);
        } else {
            fprintf(stderr, "[SkxHammerer] pair %zu RESULT: %zu flips detected\n", idx, flip_count);
        }

        SKXPairResult r{};
        r.pair = pair;
        r.hammer_iters = hammer_iters;
        r.flip_count = flip_count;
        results.push_back(r);

        if (flip_count > best_flip_count ||
            (flip_count == best_flip_count && pair.row_distance < best_distance)) {
            best_flip_count = flip_count;
            best_distance = pair.row_distance;
            best_index = (ssize_t)idx;
        }
    }

    write_csv_report("skx_pair_report.csv", results);

    fprintf(stderr, "\n[SkxHammerer] ===== FINAL SUMMARY =====\n");
    fprintf(stderr, "[SkxHammerer] tested %zu candidate pairs\n", results.size());
    fprintf(stderr, "[SkxHammerer] chosen bank for testing: %d\n", chosen_bank);

    size_t num_pairs_with_flips = 0;
    for (const auto &r : results) {
        if (r.flip_count > 0) num_pairs_with_flips++;
    }

    fprintf(stderr, "[SkxHammerer] pairs with flips: %zu\n", num_pairs_with_flips);

    if (best_index >= 0) {
        const auto &best = results[(size_t)best_index];
        fprintf(stderr,
                "[SkxHammerer] best pair index=%zd flip_count=%zu row_distance=%ld "
                "rowA=0x%llx rowB=0x%llx\n",
                best_index,
                best.flip_count,
                best.pair.row_distance,
                (unsigned long long)best.pair.a.row,
                (unsigned long long)best.pair.b.row);
    }

    munmap((void *)buf, bytes);
    SKXHAMDBG("run: complete");
    return true;
}
