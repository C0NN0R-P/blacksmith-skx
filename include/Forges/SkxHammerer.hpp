#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "Memory/SKXDecoder.hpp"

enum class SKXHammerBackend {
    SIMPLE,
    JIT
};

struct SKXPairCandidate {
    SKXHit a;
    SKXHit b;
    long row_distance;
};

struct SKXPairResult {
    SKXPairCandidate pair;
    std::string backend;
    size_t hammer_iters;
    size_t flip_count;
};

class SkxHammerer {
public:
    SkxHammerer();

    bool run(size_t bytes,
             size_t step,
             size_t max_hits,
             int target_bank,
             size_t hammer_iters);

private:
    std::vector<SKXHit> filter_to_bank(const std::vector<SKXHit> &hits, int target_bank);
    std::vector<SKXHit> filter_to_common_context(const std::vector<SKXHit> &hits);

    int choose_best_bank(const std::vector<SKXHit> &hits, int requested_bank);
    void print_bank_histogram(const std::vector<SKXHit> &hits);

    std::vector<SKXPairCandidate> build_candidate_pairs(const std::vector<SKXHit> &hits,
                                                        size_t max_pairs);
    void print_candidate_pairs(const std::vector<SKXPairCandidate> &pairs, size_t max_to_print);

    void hammer_pair_simple(volatile char *a, volatile char *b, size_t iters);
    void hammer_pair_jit(volatile char *a, volatile char *b, size_t total_activations);

    size_t scan_flips(volatile char *buf,
                      size_t bytes,
                      const std::vector<unsigned char> &baseline,
                      size_t max_report);

    bool write_csv_report(const std::string &path,
                          const std::vector<SKXPairResult> &results);

private:
    SKXDecoder decoder_;
};
