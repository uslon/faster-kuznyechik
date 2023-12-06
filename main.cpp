#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>

constexpr int BLOCK_SIZE = 16;
constexpr int FIELD_SIZE = 256;

using v128_t = uint8_t[BLOCK_SIZE];
using matrix_t = uint8_t[BLOCK_SIZE][BLOCK_SIZE];

uint8_t MT[FIELD_SIZE][FIELD_SIZE];
v128_t LTO[BLOCK_SIZE][FIELD_SIZE];
v128_t LTO_INV[BLOCK_SIZE][FIELD_SIZE];
v128_t KEY_SEQUENCE[10];

const uint8_t PI[0x100] = {
  0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,   // 00..07
  0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,   // 08..0F
  0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,   // 10..17
  0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,   // 18..1F
  0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,   // 20..27
  0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,   // 28..2F
  0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,   // 30..37
  0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,   // 38..3F
  0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,   // 40..47
  0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,   // 48..4F
  0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,   // 50..57
  0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,   // 58..5F
  0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,   // 60..67
  0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,   // 68..6F
  0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,   // 70..77
  0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,   // 78..7F
  0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,   // 80..87
  0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,   // 88..8F
  0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,   // 90..97
  0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,   // 98..9F
  0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,   // A0..A7
  0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,   // A8..AF
  0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,   // B0..B7
  0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,   // B8..BF
  0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,   // C0..C7
  0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,   // C8..CF
  0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,   // D0..D7
  0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,   // D8..DF
  0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,   // E0..E7
  0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,   // E8..EF
  0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,   // F0..F7
  0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,   // F8..FF
};

const uint8_t PI_INV[0x100] = {
  0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,   // 00..07
  0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,   // 08..0F
  0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,   // 10..17
  0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,   // 18..1F
  0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,   // 20..27
  0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,   // 28..2F
  0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,   // 30..37
  0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,   // 38..3F
  0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,   // 40..47
  0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,   // 48..4F
  0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,   // 50..57
  0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,   // 58..5F
  0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,   // 60..67
  0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,   // 68..6F
  0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,   // 70..77
  0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,   // 78..7F
  0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,   // 80..87
  0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,   // 88..8F
  0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,   // 90..97
  0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,   // 98..9F
  0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,   // A0..A7
  0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,   // A8..AF
  0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,   // B0..B7
  0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,   // B8..BF
  0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,   // C0..C7
  0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,   // C8..CF
  0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,   // D0..D7
  0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,   // D8..DF
  0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,   // E0..E7
  0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,   // E8..EF
  0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,   // F0..F7
  0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74    // F8..FF
};

inline void xor_fast(v128_t a, v128_t b) {
    __uint128_t* a_ptr = reinterpret_cast<__uint128_t *>(a);
    __uint128_t* b_ptr = reinterpret_cast<__uint128_t *>(b);
    *a_ptr ^= *b_ptr;
}


void s_box(v128_t a) {
    for (uint32_t i = 0; i < BLOCK_SIZE; ++i) {
        a[i] = PI[a[i]];
    }
}

const v128_t l_small = {
1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148,
};

const uint32_t factor = (1 << 8) + (1 << 7) + (1 << 6) + (1 << 1) + 1;

inline uint32_t get_ith(uint32_t x, uint32_t i) {
    return (x >> i) & 1;
}

uint32_t raw_multiply(uint32_t a, uint32_t b) {
    uint32_t res = 0;
    for (uint32_t i = 0; i < 8; ++i) {
        if (!get_ith(a, i)) {
            continue;
        }
        res ^= (b << i);
    }

    for (uint32_t i = 31; i > 7; --i) {
        if (!get_ith(res, i)) {
            continue;
        }
        res ^= (factor << (i - 8));
    }

    return res;
}

void precalculate_mt() {
    for (size_t i = 0; i < FIELD_SIZE; ++i) {
        for (size_t j = 0; j < FIELD_SIZE; ++j) {
            MT[i][j] = raw_multiply(i, j);
        }
    }
}

void multiply(matrix_t a, matrix_t b) {
    matrix_t res;
    for (uint32_t i = 0; i < BLOCK_SIZE; ++i) {
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            res[i][j] = 0;
            for (uint32_t k = 0; k < BLOCK_SIZE; ++k) {
                res[i][j] ^= MT[a[i][k]][b[k][j]];
            }
        }
    }
    std::memcpy((void *)a, (void *)res, BLOCK_SIZE * BLOCK_SIZE);
}

void generate_e(matrix_t mtx) {
    for (uint32_t i = 0; i < BLOCK_SIZE; ++i) {
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            mtx[i][j] = (i == j);
        }
    }
}

void power(matrix_t mtx, uint32_t n) {
    if (!n) {
        generate_e(mtx);
        return;
    }

    if (n & 1) {
        matrix_t single;
        std::memcpy((void *)single, (void *)mtx, BLOCK_SIZE * BLOCK_SIZE);

        power(mtx, n - 1);
        multiply(mtx, single);
        return;
    }

    power(mtx, n >> 1);
    multiply(mtx, mtx);
}

void precalculate_lto(matrix_t L, uint8_t lto[BLOCK_SIZE][FIELD_SIZE][BLOCK_SIZE]) {
    power(L, 16);

    for (uint32_t i = 0; i < BLOCK_SIZE; ++i) {
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            for (uint32_t x = 0; x < FIELD_SIZE; ++x) {
                lto[j][x][i] = MT[L[i][j]][x];
            }
        }
    }
}

void precalculate() {
    precalculate_mt();

    matrix_t L;
    for (uint32_t i = 0; i + 1 < BLOCK_SIZE; ++i) {
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            L[i][j] = (i + 1 == j);
        }
    }
    std::memcpy(L[BLOCK_SIZE - 1], l_small, BLOCK_SIZE);
    precalculate_lto(L, LTO);

    for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
        L[0][j] = l_small[(j + 1) % BLOCK_SIZE];
    }
    for (uint32_t i = 1; i < BLOCK_SIZE; ++i) {
        for (uint32_t j = 0; j < BLOCK_SIZE; ++j) {
            L[i][j] = (i == j + 1);
        }
    }
    precalculate_lto(L, LTO_INV);
}

void apply_lto(v128_t block, uint8_t lto[BLOCK_SIZE][FIELD_SIZE][BLOCK_SIZE]) {
    uint8_t result[16] = {};
    for (uint8_t i = 0; i < 16; ++i) {
        for (uint8_t first_ind = 0; first_ind < 16; ++first_ind) {
            result[first_ind] ^= lto[i][block[i]][first_ind];
        }
    }
    std::memcpy(block, result, 16);
}

void f_transform(v128_t lr[2], v128_t key) {
    v128_t res;
    std::memcpy(res, lr[0], BLOCK_SIZE);

    xor_fast(lr[0], key);
    s_box(lr[0]);
    apply_lto(lr[0], LTO);
    xor_fast(lr[0], lr[1]);

    std::memcpy(lr[1], res, BLOCK_SIZE);
}

void generate_keysequence(v128_t master_key[2]) {
    v128_t c[32];
    for (int i = 0; i < 32; ++i) {
        std::memset(c[i], 0, BLOCK_SIZE);
        c[i][0] = i + 1;
        apply_lto(c[i], LTO);
    }

    std::memcpy(KEY_SEQUENCE[0], master_key[0], BLOCK_SIZE);
    std::memcpy(KEY_SEQUENCE[1], master_key[1], BLOCK_SIZE);

    for (int i = 1; i < 5; ++i) {
        for (int j = 0; j < 8; ++j) {
            f_transform(master_key, c[(i - 1) * 8 + j]);
        }
        std::memcpy(KEY_SEQUENCE[2 * i], master_key[0], BLOCK_SIZE);
        std::memcpy(KEY_SEQUENCE[2 * i + 1], master_key[1], BLOCK_SIZE);
    }
}

void encrypt_block(v128_t block) {
    for (uint8_t i = 0; i < 9; ++i) {
        for (uint8_t idx = 0; idx < 16; ++idx) {
            block[idx] = PI[block[idx] ^ KEY_SEQUENCE[i][idx]];
        }
        apply_lto(block, LTO);
    }
    // xor_fast(block, KEY_SEQUENCE[9]);
    for (uint8_t idx = 0; idx < 16; ++idx) {
        block[idx] ^= KEY_SEQUENCE[9][idx];
    }
}

void decrypt_block(v128_t block) {
    for (uint8_t idx = 0; idx < 16; ++idx) {
        block[idx] ^= KEY_SEQUENCE[9][idx];
    }
    for (int8_t i = 8; i >= 0; --i) {
        apply_lto(block, LTO_INV);
        for (uint8_t idx = 0; idx < 16; ++idx) {
            block[idx] = PI_INV[block[idx]] ^ KEY_SEQUENCE[i][idx];
        }
    }
}

void string_to_v128(const std::string& str, v128_t dest) {
    assert(str.length() == 2 * 16);

    auto convert = [](char digit) {
        if (std::isalpha(digit)) {
            return digit - 'a' + 10;
        }
        return digit - '0';
    };

    for (size_t i = 0; i < str.length(); i += 2) {
        size_t j = 15 - (i >> 1);
        dest[j] = (convert(str[i]) << 4) + convert(str[i + 1]);
    }
}

std::string to_string(v128_t x) {
    auto convert = [](char digit) {
        return (digit > 9 ? digit - 10 + 'a' : digit + '0');
    };

    std::string str(32, 'x');
    for (size_t i = 0; i < str.length(); i += 2) {
        size_t j = 15 - (i >> 1);
        str[i] = convert(x[j] >> 4);
        str[i + 1] = convert(x[j] & 15);
    }

    return str;
}

inline void encrypt_data(v128_t data[6400][2048]) {
    for (size_t i = 0; i < 6400; ++i) {
        for (size_t j = 0; j < 2048; ++j) {
            encrypt_block(data[i][j]);
        }
    }
}

void decrypt_data(v128_t data[6400][2048]) {
    for (size_t i = 0; i < 6400; ++i) {
        for (size_t j = 0; j < 2048; ++j) {
            decrypt_block(data[i][j]);
        }
    }
}

void run_correctness_checks() {
    std::cout << "running correcteness checks..." << std::endl;

    assert(PI[31] == 193);
    assert(MT[128][3] == 67);

    auto data = new uint8_t[64][256][BLOCK_SIZE];
    auto initial_data = new uint8_t[64][256][BLOCK_SIZE];
    std::memcpy((uint8_t *)initial_data, (uint8_t *)data, 64 * 256 * BLOCK_SIZE);

    for (int it = 0; it < 6; ++it) {
        for (size_t i = 0; i < 64; ++i) {
            for (size_t j = 0; j < 256; ++j) {
                encrypt_block(data[i][j]);
            }
        }
    }

    for (size_t i = 0; i < 64; ++i) {
        for (size_t j = 0; j < 256; ++j) {
            for (int it = 0; it < 6; ++it) {
                decrypt_block(data[i][j]);
            }
            for (size_t k = 0; k < BLOCK_SIZE; ++k) {
                assert(data[i][j][k] == initial_data[i][j][k]);
            }
        }
    }

    delete[] data;

    std::cout << "correctness checks passed" << std::endl;
}

inline void run_benchmark() {
    auto data = new uint8_t[64][256][BLOCK_SIZE];

    std::cout << "encrypting...\n";
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    for (int it = 0; it < 800; ++it) {
        for (size_t i = 0; i < 64; ++i) {
            for (size_t j = 0; j < 256; ++j) {
                encrypt_block(data[i][j]);
            }
        }
    }

    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();
    std::cout << "encryption lasted " << std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count()
    << "ms" << std::endl;

    delete[] data;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("there must be one argument\n");
        printf("usage: %s <unit-tests / benchmark>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    precalculate();

    v128_t master_key[2];
    string_to_v128("8899aabbccddeeff0011223344556677", master_key[0]);
    string_to_v128("fedcba98765432100123456789abcdef", master_key[1]);
    generate_keysequence(master_key);


    if (strcmp(argv[1], "unit-tests") == 0) {
        run_correctness_checks();
        return 0;
    }

    if (strcmp(argv[1], "benchmark") == 0) {
        run_benchmark();
        return 0;
    }

    printf("unknown argument\n");
    printf("usage: %s <unit-tests / benchmark>\n", argv[0]);
    exit(EXIT_FAILURE);
}
