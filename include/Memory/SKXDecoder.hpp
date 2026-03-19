#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

struct SKXHit {
    volatile char *va;
    uint64_t pa;

    int socket;
    int imc;
    int channel;
    int dimm;
    int rank;

    int bank_group;
    int bank;
    int bank_id;
    uint64_t row;
    uint64_t col;
};

class SKXDecoder {
public:
    SKXDecoder();
    ~SKXDecoder();

    bool init();

    std::vector<SKXHit> collect_hits(volatile char *base,
                                     size_t bytes,
                                     size_t step,
                                     size_t max_hits);

    static uint64_t ctx_key(const SKXHit &h);
    static void debug_dump_hit(const SKXHit &h);

private:
    bool decode_one(volatile char *va, SKXHit &out_hit);
    bool virt_to_phys(volatile char *va, uint64_t &pa_out);
    bool decode_pa_to_dram(uint64_t pa, SKXHit &out_hit);

private:
    bool initialized_;
    int pagemap_fd_;
};
