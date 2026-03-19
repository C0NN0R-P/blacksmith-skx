#pragma once

#include <cstddef>
#include <vector>

#include "Memory/SKXDecoder.hpp"

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

    bool pick_two_distinct_rows(const std::vector<SKXHit> &hits,
                                size_t &left_idx,
                                size_t &right_idx);

    void hammer_pair(volatile char *a, volatile char *b, size_t iters);

private:
    SKXDecoder decoder_;
};
