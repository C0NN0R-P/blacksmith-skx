#include "Memory/SKXDecoder.hpp"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <climits>
#include <cstdarg>

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define SKXDBG(fmt, ...) fprintf(stderr, "[SKXDecoder] " fmt "\n", ##__VA_ARGS__)

#ifndef BIT_ULL
#define BIT_ULL(n) (1ULL << (n))
#endif

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) \
    (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#endif

#define GET_BITFIELD(v, lo, hi) \
    (((v) & GENMASK_ULL((hi), (lo))) >> (lo))

#define NUM_IMC 2
#define NUM_CHANNELS 3
#define NUM_DIMMS 2
#define MASK26 0x3FFFFFFULL
#define MASK29 0x1FFFFFFFULL

namespace {

/* ============================ basic helpers ============================ */

static void warnx(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

static int read_u32_file(const char *path, uint32_t *out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -errno;

    char buf[64];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (n <= 0) return -EIO;
    buf[n] = 0;

    unsigned long v = strtoul(buf, nullptr, 0);
    *out = (uint32_t)v;
    return 0;
}

static int pread_u32(int fd, off_t off, uint32_t *out) {
    uint32_t v = 0;
    ssize_t n = pread(fd, &v, sizeof(v), off);
    if (n != (ssize_t)sizeof(v)) return -errno;
    *out = v;
    return 0;
}

static int open_pci_config(const char *bdf, char *out_path, size_t out_sz) {
    snprintf(out_path, out_sz, "/sys/bus/pci/devices/%s/config", bdf);
    int fd = open(out_path, O_RDONLY);
    if (fd < 0) return -errno;
    return fd;
}

static int parse_bdf(const char *name,
                     unsigned *seg,
                     unsigned *bus,
                     unsigned *dev,
                     unsigned *fn) {
    if (sscanf(name, "%x:%x:%x.%x", seg, bus, dev, fn) != 4) return -1;
    return 0;
}

static uint8_t pci_devfn(unsigned dev, unsigned fn) {
    return (uint8_t)((dev << 3) | (fn & 7));
}

static int is_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

/* ============================ SKX structs ============================ */

struct skx_dimm {
    uint8_t close_pg;
    uint8_t bank_xor_enable;
    uint8_t fine_grain_bank;
    uint8_t rowbits;
    uint8_t colbits;
};

struct skx_channel {
    char bdf[32];
    int cfg_fd;
    struct skx_dimm dimms[NUM_DIMMS];
};

struct skx_imc {
    uint8_t mc;
    uint8_t lmc;
    uint8_t src_id;
    uint8_t node_id;
    struct skx_channel chan[NUM_CHANNELS];
};

struct skx_dev {
    struct skx_dev *next;
    uint8_t busmap[4];
    char sad_all_bdf[32];
    char util_all_bdf[32];
    int sad_all_fd;
    int util_all_fd;
    uint32_t mcroute;
    struct skx_imc imc[NUM_IMC];
};

struct decoded_addr {
    struct skx_dev *dev;
    uint64_t addr;
    int socket;
    int imc;
    int channel;
    uint64_t chan_addr;
    int sktways;
    int chanways;
    int dimm;
    int rank;
    int channel_rank;
    uint64_t rank_address;
    int row;
    int column;
    int bank_address;
    int bank_group;
};

struct pci_ent {
    char bdf[32];
    uint16_t vendor;
    uint16_t device;
    uint8_t bus;
    uint8_t devfn;
};

/* ============================ globals ============================ */

static struct skx_dev *g_skx_devs = nullptr;
static int g_skx_num_sockets = 0;
static uint64_t g_skx_tolm = 0;
static uint64_t g_skx_tohm = 0;

/* ============================ cleanup ============================ */

static void free_skx_topology(void) {
    struct skx_dev *d = g_skx_devs;
    while (d) {
        if (d->sad_all_fd >= 0) close(d->sad_all_fd);
        if (d->util_all_fd >= 0) close(d->util_all_fd);

        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                if (d->imc[mc].chan[ch].cfg_fd >= 0) {
                    close(d->imc[mc].chan[ch].cfg_fd);
                    d->imc[mc].chan[ch].cfg_fd = -1;
                }
            }
        }

        struct skx_dev *next = d->next;
        free(d);
        d = next;
    }

    g_skx_devs = nullptr;
    g_skx_num_sockets = 0;
    g_skx_tolm = 0;
    g_skx_tohm = 0;
}

/* ============================ PCI scan ============================ */

static struct pci_ent *scan_pci(size_t *out_n) {
    const char *root = "/sys/bus/pci/devices";
    DIR *d = opendir(root);
    if (!d) {
        warnx("[SKXDecoder] failed to open %s: %s", root, strerror(errno));
        return nullptr;
    }

    size_t cap = 256;
    size_t n = 0;
    struct pci_ent *arr = (struct pci_ent *)calloc(cap, sizeof(*arr));
    if (!arr) {
        closedir(d);
        return nullptr;
    }

    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", root, de->d_name);
        if (!is_dir(path)) continue;

        uint32_t v = 0, did = 0;
        char vpath[PATH_MAX], dpath[PATH_MAX];
        snprintf(vpath, sizeof(vpath), "%s/vendor", path);
        snprintf(dpath, sizeof(dpath), "%s/device", path);

        if (read_u32_file(vpath, &v) != 0) continue;
        if (read_u32_file(dpath, &did) != 0) continue;

        unsigned seg, bus, dev, fn;
        if (parse_bdf(de->d_name, &seg, &bus, &dev, &fn) != 0) continue;

        if (n == cap) {
            cap *= 2;
            struct pci_ent *tmp = (struct pci_ent *)realloc(arr, cap * sizeof(*arr));
            if (!tmp) {
                free(arr);
                closedir(d);
                return nullptr;
            }
            arr = tmp;
        }

        snprintf(arr[n].bdf, sizeof(arr[n].bdf), "%s", de->d_name);
        arr[n].vendor = (uint16_t)v;
        arr[n].device = (uint16_t)did;
        arr[n].bus = (uint8_t)bus;
        arr[n].devfn = pci_devfn(dev, fn);
        n++;
    }

    closedir(d);
    *out_n = n;
    return arr;
}

static struct pci_ent *find_first(const struct pci_ent *arr,
                                  size_t n,
                                  uint16_t vendor,
                                  uint16_t device) {
    for (size_t i = 0; i < n; i++) {
        if (arr[i].vendor == vendor && arr[i].device == device) {
            return (struct pci_ent *)&arr[i];
        }
    }
    return nullptr;
}

static struct skx_dev *get_skx_dev_by_bus(uint8_t bus, uint8_t idx) {
    for (struct skx_dev *d = g_skx_devs; d; d = d->next) {
        if (d->busmap[idx] == bus) return d;
    }
    return nullptr;
}

static int skx_get_hi_lo_from_2034(const struct pci_ent *ents, size_t nents) {
    struct pci_ent *p = find_first(ents, nents, 0x8086, 0x2034);
    if (!p) {
        warnx("[SKXDecoder] 0x2034 device not found");
        return -ENOENT;
    }

    char cfgpath[PATH_MAX];
    int fd = open_pci_config(p->bdf, cfgpath, sizeof(cfgpath));
    if (fd < 0) return fd;

    uint32_t reg = 0;
    if (pread_u32(fd, 0xD0, &reg) != 0) { close(fd); return -EIO; }
    g_skx_tolm = (uint64_t)reg;

    if (pread_u32(fd, 0xD4, &reg) != 0) { close(fd); return -EIO; }
    g_skx_tohm = (uint64_t)reg;

    if (pread_u32(fd, 0xD8, &reg) != 0) { close(fd); return -EIO; }
    g_skx_tohm |= ((uint64_t)reg << 32);

    close(fd);

    SKXDBG("TOLM=0x%llx TOHM=0x%llx",
           (unsigned long long)g_skx_tolm,
           (unsigned long long)g_skx_tohm);
    return 0;
}

static int get_all_bus_mappings(const struct pci_ent *ents, size_t nents) {
    for (size_t i = 0; i < nents; i++) {
        if (ents[i].vendor != 0x8086 || ents[i].device != 0x2016) continue;

        char cfgpath[PATH_MAX];
        int fd = open_pci_config(ents[i].bdf, cfgpath, sizeof(cfgpath));
        if (fd < 0) continue;

        uint32_t reg = 0;
        int rc = pread_u32(fd, 0xCC, &reg);
        close(fd);
        if (rc != 0) continue;

        struct skx_dev *d = (struct skx_dev *)calloc(1, sizeof(*d));
        if (!d) return -ENOMEM;

        d->busmap[0] = (uint8_t)GET_BITFIELD(reg, 0, 7);
        d->busmap[1] = (uint8_t)GET_BITFIELD(reg, 8, 15);
        d->busmap[2] = (uint8_t)GET_BITFIELD(reg, 16, 23);
        d->busmap[3] = (uint8_t)GET_BITFIELD(reg, 24, 31);

        d->sad_all_fd = -1;
        d->util_all_fd = -1;

        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                d->imc[mc].chan[ch].cfg_fd = -1;
            }
        }

        d->next = g_skx_devs;
        g_skx_devs = d;
        g_skx_num_sockets++;

        SKXDBG("socket busmap discovered: [%u %u %u %u]",
               d->busmap[0], d->busmap[1], d->busmap[2], d->busmap[3]);
    }

    return g_skx_num_sockets;
}

static int attach_unit_to_socket(struct skx_dev *d,
                                 const char *bdf,
                                 uint16_t did,
                                 uint8_t devfn) {
    int mc = -1, ch = -1;

    if (did == 0x2040) {
        if (devfn == pci_devfn(10, 0)) mc = 0;
        else if (devfn == pci_devfn(12, 0)) mc = 1;
        else return -1;
        ch = 0;
    } else if (did == 0x2044) {
        if (devfn == pci_devfn(10, 4)) mc = 0;
        else if (devfn == pci_devfn(12, 4)) mc = 1;
        else return -1;
        ch = 1;
    } else if (did == 0x2048) {
        if (devfn == pci_devfn(11, 0)) mc = 0;
        else if (devfn == pci_devfn(13, 0)) mc = 1;
        else return -1;
        ch = 2;
    } else if (did == 0x2054) {
        snprintf(d->sad_all_bdf, sizeof(d->sad_all_bdf), "%s", bdf);
        return 0;
    } else if (did == 0x2055) {
        snprintf(d->util_all_bdf, sizeof(d->util_all_bdf), "%s", bdf);
        return 0;
    } else if (did == 0x208e) {
        return 0;
    } else {
        return -1;
    }

    snprintf(d->imc[mc].chan[ch].bdf, sizeof(d->imc[mc].chan[ch].bdf), "%s", bdf);
    return 0;
}

static int get_src_id(struct skx_dev *d, uint8_t *out) {
    uint32_t reg = 0;
    if (pread_u32(d->util_all_fd, 0xF0, &reg) != 0) return -EIO;
    *out = (uint8_t)GET_BITFIELD(reg, 12, 14);
    return 0;
}

static int get_node_id(struct skx_dev *d, uint8_t *out) {
    uint32_t reg = 0;
    if (pread_u32(d->util_all_fd, 0xF4, &reg) != 0) return -EIO;
    *out = (uint8_t)GET_BITFIELD(reg, 0, 2);
    return 0;
}

static int get_all_munits_and_open(const struct pci_ent *ents, size_t nents) {
    for (size_t i = 0; i < nents; i++) {
        if (ents[i].vendor != 0x8086) continue;

        uint16_t did = ents[i].device;
        if (!(did == 0x2054 || did == 0x2055 || did == 0x2040 ||
              did == 0x2044 || did == 0x2048 || did == 0x208e)) {
            continue;
        }

        uint8_t busidx = (did == 0x2040 || did == 0x2044 || did == 0x2048) ? 2 : 1;
        struct skx_dev *d = get_skx_dev_by_bus(ents[i].bus, busidx);
        if (!d) continue;

        if (did == 0x208e) {
            char cfgpath[PATH_MAX];
            int fd = open_pci_config(ents[i].bdf, cfgpath, sizeof(cfgpath));
            if (fd < 0) continue;

            uint32_t reg = 0;
            if (pread_u32(fd, 0xB4, &reg) == 0 && reg != 0) {
                if (d->mcroute == 0) d->mcroute = reg;
            }
            close(fd);
            continue;
        }

        attach_unit_to_socket(d, ents[i].bdf, did, ents[i].devfn);
    }

    for (struct skx_dev *d = g_skx_devs; d; d = d->next) {
        if (d->sad_all_bdf[0] == 0 || d->util_all_bdf[0] == 0) {
            warnx("[SKXDecoder] missing sad_all/util_all for socket [%u %u %u %u]",
                  d->busmap[0], d->busmap[1], d->busmap[2], d->busmap[3]);
            continue;
        }

        char path[PATH_MAX];

        d->sad_all_fd = open_pci_config(d->sad_all_bdf, path, sizeof(path));
        d->util_all_fd = open_pci_config(d->util_all_bdf, path, sizeof(path));

        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                if (d->imc[mc].chan[ch].bdf[0] == 0) continue;
                d->imc[mc].chan[ch].cfg_fd =
                    open_pci_config(d->imc[mc].chan[ch].bdf, path, sizeof(path));
            }
        }

        if (d->util_all_fd >= 0) {
            uint8_t src = 0, node = 0;
            if (get_src_id(d, &src) == 0 && get_node_id(d, &node) == 0) {
                for (int mc = 0; mc < NUM_IMC; mc++) {
                    d->imc[mc].src_id = src;
                    d->imc[mc].node_id = node;
                    d->imc[mc].lmc = (uint8_t)mc;
                }
            }
        }
    }

    return 0;
}

/* ============================ DIMM params ============================ */

static int get_dimm_attr(uint32_t reg,
                         int lobit,
                         int hibit,
                         int add,
                         int minval,
                         int maxval) {
    uint32_t val = (uint32_t)GET_BITFIELD(reg, lobit, hibit);
    if ((int)val < minval || (int)val > maxval) return -EINVAL;
    return (int)val + add;
}

#define IS_DIMM_PRESENT(mtr) GET_BITFIELD((mtr), 15, 15)

static int numrank(uint32_t reg) { return get_dimm_attr(reg, 12, 13, 0, 1, 2); }
static int numrow(uint32_t reg)  { return get_dimm_attr(reg,  2,  4, 12, 1, 6); }
static int numcol(uint32_t reg)  { return get_dimm_attr(reg,  0,  1, 10, 0, 2); }

static int skx_load_dimm_params(void) {
    for (struct skx_dev *d = g_skx_devs; d; d = d->next) {
        for (int mc = 0; mc < NUM_IMC; mc++) {
            for (int ch = 0; ch < NUM_CHANNELS; ch++) {
                int fd = d->imc[mc].chan[ch].cfg_fd;
                if (fd < 0) continue;

                uint32_t amap = 0;
                if (pread_u32(fd, 0x8C, &amap) != 0) continue;

                for (int j = 0; j < NUM_DIMMS; j++) {
                    uint32_t mtr = 0;
                    if (pread_u32(fd, 0x80 + 4 * j, &mtr) != 0) continue;
                    if (!IS_DIMM_PRESENT(mtr)) continue;

                    int rows = numrow(mtr);
                    int cols = numcol(mtr);
                    (void)numrank(mtr);

                    struct skx_dimm *sd = &d->imc[mc].chan[ch].dimms[j];
                    sd->close_pg         = (uint8_t)GET_BITFIELD(mtr, 0, 0);
                    sd->bank_xor_enable  = (uint8_t)GET_BITFIELD(mtr, 9, 9);
                    sd->fine_grain_bank  = (uint8_t)GET_BITFIELD(amap, 0, 0);
                    sd->rowbits          = (uint8_t)rows;
                    sd->colbits          = (uint8_t)cols;

                    SKXDBG("DIMM params mc=%d ch=%d dimm=%d close_pg=%u bank_xor=%u fine=%u rowbits=%u colbits=%u",
                           mc, ch, j,
                           sd->close_pg,
                           sd->bank_xor_enable,
                           sd->fine_grain_bank,
                           sd->rowbits,
                           sd->colbits);
                }
            }
        }
    }
    return 0;
}

/* ============================ decode ============================ */

#define SKX_MAX_SAD 24
#define SKX_MAX_TAD 8
#define SKX_MAX_RIR 4

static int SKX_GET_SAD(struct skx_dev *d, int i, uint32_t *sad) {
    return pread_u32(d->sad_all_fd, 0x60 + 8 * i, sad);
}
static int SKX_GET_ILV(struct skx_dev *d, int i, uint32_t *ilv) {
    return pread_u32(d->sad_all_fd, 0x64 + 8 * i, ilv);
}
static int SKX_GET_TADBASE(struct skx_dev *d, int mc, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[0].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x850 + 4 * i, reg);
}
static int SKX_GET_TADWAYNESS(struct skx_dev *d, int mc, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[0].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x880 + 4 * i, reg);
}
static int SKX_GET_TADCHNILVOFFSET(struct skx_dev *d, int mc, int ch, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x90 + 4 * i, reg);
}
static int SKX_GET_RIRWAYNESS(struct skx_dev *d, int mc, int ch, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x108 + 4 * i, reg);
}
static int SKX_GET_RIRILV(struct skx_dev *d, int mc, int ch, int idx, int i, uint32_t *reg) {
    int fd = d->imc[mc].chan[ch].cfg_fd;
    if (fd < 0) return -ENOENT;
    return pread_u32(fd, 0x120 + 16 * idx + 4 * i, reg);
}

/* SAD */
#define SKX_SAD_MOD3MODE(sad)    GET_BITFIELD((sad), 30, 31)
#define SKX_SAD_MOD3(sad)        GET_BITFIELD((sad), 27, 27)
#define SKX_SAD_LIMIT(sad)       ((((uint64_t)GET_BITFIELD((sad), 7, 26)) << 26) | MASK26)
#define SKX_SAD_MOD3ASMOD2(sad)  GET_BITFIELD((sad), 5, 6)
#define SKX_SAD_INTERLEAVE(sad)  GET_BITFIELD((sad), 1, 2)
#define SKX_SAD_ENABLE(sad)      GET_BITFIELD((sad), 0, 0)
#define SKX_ILV_REMOTE(tgt)      ((((tgt) & 8) == 0))
#define SKX_ILV_TARGET(tgt)      ((tgt) & 7)

/* TAD */
#define SKX_TAD_BASE(b)          (((uint64_t)GET_BITFIELD((b), 12, 31)) << 26)
#define SKX_TAD_SKT_GRAN(b)      GET_BITFIELD((b), 4, 5)
#define SKX_TAD_CHN_GRAN(b)      GET_BITFIELD((b), 6, 7)
#define SKX_TAD_LIMIT(b)         ((((uint64_t)GET_BITFIELD((b), 12, 31)) << 26) | MASK26)
#define SKX_TAD_OFFSET(b)        (((uint64_t)GET_BITFIELD((b), 4, 23)) << 26)
#define SKX_TAD_SKTWAYS(b)       (1 << GET_BITFIELD((b), 10, 11))
#define SKX_TAD_CHNWAYS(b)       (GET_BITFIELD((b), 8, 9) + 1)

/* RIR */
#define SKX_RIR_VALID(b)         GET_BITFIELD((b), 31, 31)
#define SKX_RIR_LIMIT(b)         ((((uint64_t)GET_BITFIELD((b), 1, 11)) << 29) | MASK29)
#define SKX_RIR_WAYS(b)          (1 << GET_BITFIELD((b), 28, 29))
#define SKX_RIR_CHAN_RANK(b)     GET_BITFIELD((b), 16, 19)
#define SKX_RIR_OFFSET(b)        (((uint64_t)GET_BITFIELD((b), 2, 15)) << 26)

static int skx_granularity[] = { 6, 8, 12, 30 };

static uint64_t skx_do_interleave(uint64_t addr,
                                  int shift,
                                  int ways,
                                  uint64_t lowbits) {
    addr >>= shift;
    addr /= (uint64_t)ways;
    addr <<= shift;
    return addr | (lowbits & ((1ULL << shift) - 1));
}

static bool skx_sad_decode(struct decoded_addr *res) {
    struct skx_dev *d0 = g_skx_devs;
    if (!d0) return false;

    struct skx_dev *d = d0;
    uint64_t addr = res->addr;

    if (addr >= g_skx_tohm || (addr >= g_skx_tolm && addr < BIT_ULL(32))) {
        SKXDBG("sad: address 0x%llx out of range tolm=0x%llx tohm=0x%llx",
               (unsigned long long)addr,
               (unsigned long long)g_skx_tolm,
               (unsigned long long)g_skx_tohm);
        return false;
    }

    int remote = 0;

restart:
    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_SAD; i++) {
        uint32_t sad = 0;
        if (SKX_GET_SAD(d, i, &sad) != 0) continue;

        uint64_t limit = SKX_SAD_LIMIT(sad);
        if (SKX_SAD_ENABLE(sad) && addr >= prev_limit && addr <= limit) {
            uint32_t ilv = 0;
            if (SKX_GET_ILV(d, i, &ilv) != 0) return false;

            int idx = 0;
            switch (SKX_SAD_INTERLEAVE(sad)) {
                case 0: idx = (int)GET_BITFIELD(addr, 6, 8); break;
                case 1: idx = (int)GET_BITFIELD(addr, 8, 10); break;
                case 2: idx = (int)GET_BITFIELD(addr, 12, 14); break;
                case 3: idx = (int)GET_BITFIELD(addr, 30, 32); break;
                default: return false;
            }

            int tgt = (int)GET_BITFIELD(ilv, 4 * idx, 4 * idx + 3);
            if (SKX_ILV_REMOTE(tgt)) {
                if (remote) return false;
                remote = 1;
                int want = SKX_ILV_TARGET(tgt);
                for (struct skx_dev *x = g_skx_devs; x; x = x->next) {
                    if (x->imc[0].src_id == want) {
                        d = x;
                        goto restart;
                    }
                }
                return false;
            }

            int lchan = 0;
            int shift = 0;

            if (SKX_SAD_MOD3(sad) == 0) {
                lchan = SKX_ILV_TARGET(tgt);
            } else {
                switch (SKX_SAD_MOD3MODE(sad)) {
                    case 0: shift = 6; break;
                    case 1: shift = 8; break;
                    case 2: shift = 12; break;
                    default: return false;
                }

                switch (SKX_SAD_MOD3ASMOD2(sad)) {
                    case 0: lchan = (int)((addr >> shift) % 3); break;
                    case 1: lchan = (int)((addr >> shift) % 2); break;
                    case 2:
                        lchan = (int)((addr >> shift) % 2);
                        lchan = (lchan << 1) | (~lchan & 1);
                        break;
                    case 3:
                        lchan = (int)(((addr >> shift) % 2) << 1);
                        break;
                    default:
                        return false;
                }

                lchan = (lchan << 1) | (SKX_ILV_TARGET(tgt) & 1);
            }

            res->dev = d;
            res->socket = d->imc[0].src_id;

            if (d->mcroute == 0) return false;

            res->imc = (int)GET_BITFIELD(d->mcroute, lchan * 3, lchan * 3 + 2);
            res->channel = (int)GET_BITFIELD(d->mcroute, lchan * 2 + 18, lchan * 2 + 19);

            SKXDBG("sad: pa=0x%llx socket=%d imc=%d ch=%d",
                   (unsigned long long)addr,
                   res->socket, res->imc, res->channel);
            return true;
        }

        prev_limit = limit + 1;
    }

    return false;
}

static bool skx_tad_decode(struct decoded_addr *res) {
    for (int i = 0; i < SKX_MAX_TAD; i++) {
        uint32_t base = 0, wayness = 0;
        if (SKX_GET_TADBASE(res->dev, res->imc, i, &base) != 0) continue;
        if (SKX_GET_TADWAYNESS(res->dev, res->imc, i, &wayness) != 0) continue;

        if (SKX_TAD_BASE(base) <= res->addr && res->addr <= SKX_TAD_LIMIT(wayness)) {
            res->sktways = (int)SKX_TAD_SKTWAYS(wayness);
            res->chanways = (int)SKX_TAD_CHNWAYS(wayness);

            int skt_interleave_bit = skx_granularity[SKX_TAD_SKT_GRAN(base)];
            int chn_interleave_bit = skx_granularity[SKX_TAD_CHN_GRAN(base)];

            uint32_t chnilvoffset = 0;
            if (SKX_GET_TADCHNILVOFFSET(res->dev, res->imc, res->channel, i, &chnilvoffset) != 0) {
                return false;
            }

            uint64_t channel_addr = res->addr - SKX_TAD_OFFSET(chnilvoffset);

            if (res->chanways == 3 && skt_interleave_bit > chn_interleave_bit) {
                channel_addr = skx_do_interleave(channel_addr, chn_interleave_bit, res->chanways, channel_addr);
                channel_addr = skx_do_interleave(channel_addr, skt_interleave_bit, res->sktways, channel_addr);
            } else {
                channel_addr = skx_do_interleave(channel_addr, skt_interleave_bit, res->sktways, res->addr);
                channel_addr = skx_do_interleave(channel_addr, chn_interleave_bit, res->chanways, res->addr);
            }

            res->chan_addr = channel_addr;

            SKXDBG("tad: pa=0x%llx chan_addr=0x%llx sktways=%d chanways=%d",
                   (unsigned long long)res->addr,
                   (unsigned long long)res->chan_addr,
                   res->sktways, res->chanways);
            return true;
        }
    }

    return false;
}

static bool skx_rir_decode(struct decoded_addr *res) {
    struct skx_dimm *dimm0 = &res->dev->imc[res->imc].chan[res->channel].dimms[0];
    int shift = dimm0->close_pg ? 6 : 13;

    uint64_t prev_limit = 0;
    for (int i = 0; i < SKX_MAX_RIR; i++) {
        uint32_t rirway = 0;
        if (SKX_GET_RIRWAYNESS(res->dev, res->imc, res->channel, i, &rirway) != 0) continue;

        uint64_t limit = SKX_RIR_LIMIT(rirway);
        if (SKX_RIR_VALID(rirway) && prev_limit <= res->chan_addr && res->chan_addr <= limit) {
            uint64_t rank_addr = res->chan_addr >> shift;
            rank_addr /= (uint64_t)SKX_RIR_WAYS(rirway);
            rank_addr <<= shift;
            rank_addr |= (res->chan_addr & GENMASK_ULL(shift - 1, 0));

            int idx = (int)((res->chan_addr >> shift) % SKX_RIR_WAYS(rirway));

            uint32_t rirlv = 0;
            if (SKX_GET_RIRILV(res->dev, res->imc, res->channel, idx, i, &rirlv) != 0) {
                return false;
            }

            res->rank_address = rank_addr - SKX_RIR_OFFSET(rirlv);

            int chan_rank = (int)SKX_RIR_CHAN_RANK(rirlv);
            res->channel_rank = chan_rank;
            res->dimm = chan_rank / 4;
            res->rank = chan_rank % 4;

            SKXDBG("rir: chan_addr=0x%llx rank_addr=0x%llx dimm=%d rank=%d",
                   (unsigned long long)res->chan_addr,
                   (unsigned long long)res->rank_address,
                   res->dimm, res->rank);
            return true;
        }

        prev_limit = limit;
    }

    return false;
}

/* MAD tables */
static uint8_t skx_close_row[]        = {15,16,17,18,20,21,22,28,10,11,12,13,29,30,31,32,33};
static uint8_t skx_close_column[]     = {3,4,5,14,19,23,24,25,26,27};
static uint8_t skx_open_row[]         = {14,15,16,20,28,21,22,23,24,25,26,27,29,30,31,32,33};
static uint8_t skx_open_column[]      = {3,4,5,6,7,8,9,10,11,12};
static uint8_t skx_open_fine_column[] = {3,4,5,7,8,9,10,11,12,13};

static int skx_bits(uint64_t addr, int nbits, uint8_t *bits) {
    int res = 0;
    for (int i = 0; i < nbits; i++) {
        res |= (int)(((addr >> bits[i]) & 1ULL) << i);
    }
    return res;
}

static int skx_bank_bits(uint64_t addr,
                         int b0,
                         int b1,
                         int do_xor,
                         int x0,
                         int x1) {
    int ret = (int)GET_BITFIELD(addr, b0, b0) |
              ((int)GET_BITFIELD(addr, b1, b1) << 1);

    if (do_xor) {
        ret ^= (int)GET_BITFIELD(addr, x0, x0) |
               ((int)GET_BITFIELD(addr, x1, x1) << 1);
    }

    return ret;
}

static bool skx_mad_decode(struct decoded_addr *r) {
    struct skx_dimm *dimm = &r->dev->imc[r->imc].chan[r->channel].dimms[r->dimm];
    int bg0 = dimm->fine_grain_bank ? 6 : 13;

    if (dimm->close_pg) {
        r->row = skx_bits(r->rank_address, dimm->rowbits, skx_close_row);
        r->column = skx_bits(r->rank_address, dimm->colbits, skx_close_column);
        r->column |= 0x400;

        r->bank_address = skx_bank_bits(r->rank_address, 8, 9,
                                        dimm->bank_xor_enable, 22, 28);
        r->bank_group = skx_bank_bits(r->rank_address, 6, 7,
                                      dimm->bank_xor_enable, 20, 21);
    } else {
        r->row = skx_bits(r->rank_address, dimm->rowbits, skx_open_row);

        if (dimm->fine_grain_bank) {
            r->column = skx_bits(r->rank_address, dimm->colbits, skx_open_fine_column);
        } else {
            r->column = skx_bits(r->rank_address, dimm->colbits, skx_open_column);
        }

        r->bank_address = skx_bank_bits(r->rank_address, 18, 19,
                                        dimm->bank_xor_enable, 22, 23);
        r->bank_group = skx_bank_bits(r->rank_address, bg0, 17,
                                      dimm->bank_xor_enable, 20, 21);
    }

    r->row &= (1u << dimm->rowbits) - 1;

    SKXDBG("mad: row=%d col=%d bg=%d bank=%d",
           r->row, r->column, r->bank_group, r->bank_address);
    return true;
}

static bool skx_decode(struct decoded_addr *res) {
    return skx_sad_decode(res) &&
           skx_tad_decode(res) &&
           skx_rir_decode(res) &&
           skx_mad_decode(res);
}

} // anonymous namespace

/* ============================ public class ============================ */

SKXDecoder::SKXDecoder()
    : initialized_(false),
      pagemap_fd_(-1) {
    SKXDBG("constructor");
}

SKXDecoder::~SKXDecoder() {
    if (pagemap_fd_ >= 0) {
        close(pagemap_fd_);
        pagemap_fd_ = -1;
    }
    free_skx_topology();
}

bool SKXDecoder::init() {
    SKXDBG("init() start");

    if (initialized_) {
        SKXDBG("already initialized");
        return true;
    }

    free_skx_topology();

    pagemap_fd_ = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd_ < 0) {
        fprintf(stderr, "[SKXDecoder] ERROR: open(/proc/self/pagemap) failed: %s\n",
                strerror(errno));
        return false;
    }

    size_t nents = 0;
    struct pci_ent *ents = scan_pci(&nents);
    if (!ents) {
        fprintf(stderr, "[SKXDecoder] ERROR: PCI scan failed\n");
        return false;
    }

    SKXDBG("PCI scan found %zu entries", nents);

    if (skx_get_hi_lo_from_2034(ents, nents) != 0) {
        fprintf(stderr, "[SKXDecoder] ERROR: failed to read TOLM/TOHM\n");
        free(ents);
        return false;
    }

    int sockets = get_all_bus_mappings(ents, nents);
    if (sockets <= 0) {
        fprintf(stderr, "[SKXDecoder] ERROR: no SKX socket bus mappings found\n");
        free(ents);
        return false;
    }

    SKXDBG("discovered %d socket bus mappings", sockets);

    if (get_all_munits_and_open(ents, nents) != 0) {
        fprintf(stderr, "[SKXDecoder] ERROR: failed to attach/open SKX units\n");
        free(ents);
        return false;
    }

    if (skx_load_dimm_params() != 0) {
        fprintf(stderr, "[SKXDecoder] ERROR: failed to load DIMM params\n");
        free(ents);
        return false;
    }

    free(ents);
    initialized_ = true;

    SKXDBG("init() complete");
    return true;
}

uint64_t SKXDecoder::ctx_key(const SKXHit &h) {
    return ((uint64_t)(uint32_t)h.socket << 32) |
           ((uint64_t)(uint32_t)h.imc << 24) |
           ((uint64_t)(uint32_t)h.channel << 16) |
           ((uint64_t)(uint32_t)h.dimm << 8) |
           ((uint64_t)(uint32_t)h.rank);
}

void SKXDecoder::debug_dump_hit(const SKXHit &h) {
    fprintf(stderr,
            "[SKXDecoder] HIT va=%p pa=0x%llx socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=0x%llx col=0x%llx\n",
            (void *)h.va,
            (unsigned long long)h.pa,
            h.socket,
            h.imc,
            h.channel,
            h.dimm,
            h.rank,
            h.bank_group,
            h.bank,
            h.bank_id,
            (unsigned long long)h.row,
            (unsigned long long)h.col);
}

bool SKXDecoder::virt_to_phys(volatile char *va, uint64_t &pa_out) {
    if (pagemap_fd_ < 0) return false;

    const uint64_t page_size = (uint64_t)sysconf(_SC_PAGESIZE);
    const uint64_t virt = (uint64_t)va;
    const uint64_t vpn = virt / page_size;
    const off_t offset = (off_t)(vpn * sizeof(uint64_t));

    uint64_t entry = 0;
    ssize_t n = pread(pagemap_fd_, &entry, sizeof(entry), offset);
    if (n != (ssize_t)sizeof(entry)) {
        fprintf(stderr, "[SKXDecoder] ERROR: pread(pagemap) failed for va=%p: %s\n",
                (void *)va, strerror(errno));
        return false;
    }

    const uint64_t present = (entry >> 63) & 1ULL;
    if (!present) return false;

    const uint64_t pfn = entry & ((1ULL << 55) - 1ULL);
    if (pfn == 0) return false;

    pa_out = pfn * page_size + (virt % page_size);
    return true;
}

bool SKXDecoder::decode_pa_to_dram(uint64_t pa, SKXHit &out_hit) {
    struct decoded_addr r;
    memset(&r, 0, sizeof(r));
    r.addr = pa;

    SKXDBG("decode_pa_to_dram: start pa=0x%llx", (unsigned long long)pa);

    if (!skx_decode(&r)) {
        SKXDBG("decode_pa_to_dram: skx_decode failed for pa=0x%llx",
               (unsigned long long)pa);
        return false;
    }

    out_hit.socket = r.socket;
    out_hit.imc = r.imc;
    out_hit.channel = r.channel;
    out_hit.dimm = r.dimm;
    out_hit.rank = r.rank;
    out_hit.row = (uint64_t)r.row;
    out_hit.col = (uint64_t)r.column;
    out_hit.bank_group = r.bank_group;
    out_hit.bank = r.bank_address;
    out_hit.bank_id = out_hit.bank_group * 4 + out_hit.bank;

    SKXDBG("decode_pa_to_dram: success socket=%d imc=%d ch=%d dimm=%d rank=%d bg=%d bank=%d bank_id=%d row=%llu col=%llu",
           out_hit.socket, out_hit.imc, out_hit.channel, out_hit.dimm, out_hit.rank,
           out_hit.bank_group, out_hit.bank, out_hit.bank_id,
           (unsigned long long)out_hit.row,
           (unsigned long long)out_hit.col);

    return true;
}

bool SKXDecoder::decode_one(volatile char *va, SKXHit &out_hit) {
    uint64_t pa = 0;
    if (!virt_to_phys(va, pa)) {
        return false;
    }

    out_hit.va = va;
    out_hit.pa = pa;

    if (!decode_pa_to_dram(pa, out_hit)) {
        return false;
    }

    debug_dump_hit(out_hit);
    return true;
}

std::vector<SKXHit> SKXDecoder::collect_hits(volatile char *base,
                                             size_t bytes,
                                             size_t step,
                                             size_t max_hits) {
    std::vector<SKXHit> hits;

    SKXDBG("collect_hits: base=%p bytes=%zu step=%zu max_hits=%zu",
           (void *)base, bytes, step, max_hits);

    if (!initialized_) {
        SKXDBG("collect_hits: decoder not initialized");
        return hits;
    }

    size_t attempts = 0;
    size_t successes = 0;

    for (size_t off = 0; off < bytes; off += step) {
        volatile char *va = base + off;
        SKXHit hit{};

        attempts++;
        if (decode_one(va, hit)) {
            hits.push_back(hit);
            successes++;

            fprintf(stderr,
                    "[SKXDecoder] collect_hits success: attempts=%zu successes=%zu offset=0x%zx bank_id=%d row=0x%llx\n",
                    attempts,
                    successes,
                    off,
                    hit.bank_id,
                    (unsigned long long)hit.row);

            if (successes >= max_hits) {
                SKXDBG("collect_hits: reached max_hits");
                break;
            }
        } else {
            if ((attempts % 1024) == 0) {
                fprintf(stderr,
                        "[SKXDecoder] collect_hits miss: attempts=%zu offset=0x%zx\n",
                        attempts, off);
            }
        }
    }

    SKXDBG("collect_hits: done attempts=%zu successes=%zu", attempts, successes);
    return hits;
}
