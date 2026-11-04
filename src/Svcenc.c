/*
 * svcenc - SNK vs. Capcom SVC Chaos / Metal Slug 5
 *   plaintext C-ROM  ->  JAMMA PCB (NEO-MVH MVO) encrypted C-ROM
 *
 * MAME's svcpcb init does:   stored --svcpcb_gfx_decrypt--> --cmc50_gfx_decrypt(key)--> plaintext
 * This tool performs the exact inverse:  plaintext --cmc50 inverse--> --svcpcb inverse--> stored
 * Tables/algorithms are taken from MAME (neocrypt / prot_cmc / neopcb), BSD-3-Clause.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef uint8_t u8;
typedef uint32_t u32;

#define SPR_SIZE 0x4000000u   /* 64MB */
static u32 TAIL_SIZE = 0x80000u;    /* S data at end of C data (svc: 0x80000, ms5: 0x20000) */

static u8 T0_03[256], T0_12[256], T1_03[256], T1_12[256];
static u8 A8_1[256], A8_2[256], A16_1[256], A16_2[256], A0[256];

static const char *S_T0_03 =
"10 61 f1 78 85 52 68 e3 12 0d fa f0 c9 36 5e 3d f9 a6 01 2e c7 84 ea 2b 6d 14 38 4f 55 1c 9d a7 "
"7a c6 f8 9a e6 42 b5 ed 7d 3a b1 05 43 4a 22 fd ac a4 31 c3 32 76 95 9e 7e 88 8e a2 97 18 be 2a "
"f5 d6 ca cc 72 3b 87 6c de 75 d7 21 cb 0b dd e7 e1 65 aa b9 44 fb 66 15 1a 3c 98 cf 8a df 37 a5 "
"2f 67 d2 83 b6 6b fc e0 b4 7c 08 dc 93 30 ab e4 19 c2 8b eb a0 0a c8 03 c0 4b 64 71 86 9c 9b 16 "
"79 ff 70 09 8c d0 f6 53 07 73 d4 89 b3 00 e9 fe ec 8f bc b2 1e 5d 11 35 a9 06 59 9f c1 d3 7b f2 "
"c5 77 4e 39 20 d5 6a 82 da 45 f3 33 81 23 ba e2 1d 5f 5c 51 49 ae 8d c4 a8 f7 1f 0f 34 28 a1 d9 "
"27 d8 4c 2c bf 91 3e 69 57 41 25 0c 5a 90 92 b0 63 6f 40 af 74 b8 2d 80 bb 46 94 e5 29 ee b7 1b "
"96 ad 13 0e 58 99 60 4d 17 26 ce e8 db ef 24 a3 6e 7f 54 3f 02 d1 5b 50 56 48 f4 bd 62 47 04 cd";

static const char *S_T0_12 =
"f4 28 b4 8f fa eb 8e 54 2b 49 d1 76 71 47 8b 57 92 85 7c b8 5c 22 f9 26 bc 5b 6d 67 ae 5f 6f f5 "
"9f 48 66 40 0d 11 4e b2 6b 35 15 0f 18 25 1d ba d3 69 79 ec a8 8c c9 7f 4b db 51 af ca e2 b3 81 "
"12 5e 7e 38 c8 95 01 ff fd fb f2 74 62 14 a5 98 a6 da 80 53 e8 56 ac 1b 52 d0 f1 45 42 b6 1a 4a "
"3a 99 fc d2 9c cf 31 2d dd 86 2f 29 e1 03 19 a2 41 33 83 90 c1 bf 0b 08 3d d8 8d 6c 39 a0 e3 55 "
"02 50 46 e6 c3 82 36 13 75 ab 27 d7 1f 0a d4 89 59 4f c0 5d c6 f7 88 bd 3c 00 ef cd 05 1c aa 9b "
"ed 7a 61 17 93 fe 23 b9 f3 68 78 f6 5a 7b e0 e4 a3 ee 16 72 c7 3b 8a 37 2a 70 a9 2c 21 f8 24 09 "
"ce 20 9e 06 87 c5 04 64 43 7d 4d 10 d6 a4 94 4c 60 de df 58 b1 44 3f b0 d9 e5 cb bb be ea 07 34 "
"73 6a 77 f0 9d 0c 2e 0e 91 9a cc c2 b7 63 97 d5 dc c4 32 e7 84 3e 30 a1 1e b5 6e 65 e9 ad a7 96";

static const char *S_T1_03 =
"9a 2f cc 4e 40 69 ac ca a5 7b 0a 61 91 0d 55 74 cd 8b 0b 80 09 5e 38 c7 da bf f5 37 23 31 33 e9 "
"ae 87 e5 fa 6e 5c ad f4 76 62 9f 2e 01 e2 f6 47 8c 7c aa 98 b5 92 51 ec 5f 07 5d 6f 16 a1 1d a9 "
"48 45 f0 6a 9c 1e 11 a0 06 46 d5 f1 73 ed 94 f7 c3 57 1b e0 97 b1 a4 a7 24 e7 2b 05 5b 34 0c b8 "
"0f 9b c8 4d 5a a6 86 3e 14 29 84 58 90 db 2d 54 9d 82 d4 7d c6 67 41 89 c1 13 b0 9e 81 6d a8 59 "
"bd 39 8e e6 25 8f d9 a2 e4 53 c5 72 7e 36 4a 4f 52 c2 22 2a ce 3c 21 2c 00 d7 75 8a 27 ee 43 fe "
"cb 6b b9 a3 78 b7 85 02 20 d0 83 c4 12 f9 fd d8 79 64 3a 49 03 b4 c0 f2 df 15 93 08 35 ff 70 dd "
"28 6c 0e 04 de 7a 65 d2 ab 42 95 e1 3f 3b 7f 66 d1 8d e3 bb 1c fc 77 1a 88 18 19 68 1f 56 d6 e8 "
"b6 bc d3 ea 3d 26 b3 c9 44 dc f3 32 30 ef 96 4c af 17 f8 fb 60 50 eb 4b 99 63 ba b2 71 cf 10 be";

static const char *S_T1_12 =
"da a7 d6 6e 2f 5e f0 3f a4 ce d3 fd 46 2a ac c9 be eb 9f d5 3c 61 96 11 d0 38 ca 06 ed 1b 65 e7 "
"23 dd d9 05 bf 5b 5d a5 95 00 ec f1 01 a9 a6 fc bb 54 e3 2e 92 58 0a 7b b6 cc b1 5f 14 35 72 ff "
"e6 52 d7 8c f3 43 af 9c c0 4f 0c 42 8e ef 80 cd 1d 7e 88 3b 98 a1 ad e4 9d 8d 2b 56 b5 50 df 66 "
"6d d4 60 09 e1 ee 4a 47 f9 fe 73 07 89 a8 39 ea 82 9e cf 26 b2 4e c3 59 f2 3d 9a b0 69 f7 bc 34 "
"e5 36 22 fb 57 71 99 6c 83 30 55 c2 bd f4 77 e9 76 97 a0 e0 b9 86 6b a3 84 67 1a 70 02 5a 41 5c "
"25 81 aa 28 78 4b c6 64 53 16 4d 8b 20 93 ae 0f 94 2c 3a c7 62 e8 c4 db 04 c5 fa 29 48 d1 08 24 "
"0d e2 d8 10 b4 91 8a 13 0e dc d2 79 b8 f8 ba 2d cb f5 7d 37 51 40 31 a2 0b 18 63 7f b3 ab 9b 87 "
"f6 90 de c8 27 45 7c 1c 85 68 33 19 03 75 15 7a 1f 49 8f 4c c1 44 17 12 6f 32 b7 3e 74 1e 21 6a";

static const char *S_A8_1 =
"fc 9b 1c 35 72 53 d6 7d 84 a4 c5 93 7b e7 47 d5 24 a2 fa 19 0c b1 8c b9 9d d8 59 4f 3c b2 78 4a "
"2a 96 9a f1 1f 22 a8 5b 67 a3 0f 00 fb df eb 0a 57 b8 25 d7 f0 6b 0b 31 95 23 2d 5c 27 c7 f4 55 "
"1a f7 74 be d3 ac 3d c1 7f bd 28 01 10 e5 09 37 1e 58 af 17 f2 16 30 92 36 68 e6 d4 ea b7 75 54 "
"77 41 b4 8d e0 f3 51 03 a9 e8 66 ab 29 a5 ed cb d1 aa f5 db 4c 42 97 8a ae c9 6e 04 33 85 dd 2b "
"6f ef 12 21 7a a1 5a 91 c8 cc c0 a7 60 3e 56 2f e4 71 99 c2 a0 45 80 65 bb 87 69 81 73 ca f6 46 "
"43 da 26 7e 8f e1 8b fd 50 79 ba c6 63 4b b3 8e 34 e2 48 14 cd e3 c4 05 13 40 06 6c 88 b0 e9 1b "
"4d f8 76 02 44 94 cf 32 fe ce 3b 5d 2c 89 5f dc d2 9c 6a ec 18 6d 0e 86 ff 5e 9e ee 11 d0 49 52 "
"4e 61 90 0d c3 39 15 83 b5 62 3f 70 7c ad 20 bf 2e 08 1d f9 b6 a6 64 07 82 38 98 3a 9f de bc d9";

static const char *S_A8_2 =
"00 be 06 5a fa 42 15 f2 3f 0a 84 93 4e 78 3b 89 32 98 a2 87 73 dd 26 e5 05 71 08 6e 9b e0 df 9e "
"fc 83 81 ef b2 c0 c3 bf a7 6d 1b 95 ed b9 3e 13 b0 47 9c 7a 24 41 68 d0 36 0b b5 c2 67 f7 54 92 "
"1e 44 86 2b 94 cc ba 23 0d ca 6b 4c 2a 9a 2d 8b e3 52 29 f0 21 bd bb 1f a3 ab f8 46 b7 45 82 5e "
"db 07 5d e9 9d 1a 48 ce 91 12 d4 ee a9 39 f1 18 2c 22 8a 7e 34 4a 8c c1 14 f3 20 35 d9 96 33 77 "
"9f 76 7c 90 c6 d5 a1 5b ac 75 c7 0c b3 17 d6 99 56 a6 3d 1d b1 2e d8 bc 2f de 60 55 6c 40 cd 43 "
"ff ad 38 79 51 c8 0e 5f c4 66 cb a8 7d a4 3a ea 27 7b 70 8e 5c 19 0f 80 6f 8f 10 f9 49 85 69 7f "
"eb 1c 01 65 37 a5 28 e4 6a 03 04 d1 31 11 30 fb 88 97 d3 f6 c5 4d f5 3c e8 61 dc d2 b4 b8 a0 ae "
"16 25 02 09 fe cf 53 63 af 59 f4 e1 ec d7 e7 50 e2 c9 aa 4b 8d 4f e6 64 da 74 b6 72 57 62 fd 58";

static const char *S_A16_1 =
"45 9f 6e 2f 28 bc 5e 6d da b5 0d b8 c0 8e a2 32 ee cd 8d 48 8c 27 14 eb 65 d7 f2 93 99 90 91 fc "
"5f cb fa 75 3f 26 de 72 33 39 c7 1f 88 79 73 ab 4e 36 5d 44 d2 41 a0 7e a7 8b a6 bf 03 d8 86 dc "
"2c aa 70 3d 46 07 80 58 0b 2b e2 f0 b1 fe 42 f3 e9 a3 85 78 c3 d0 5a db 1a fb 9d 8a a5 12 0e 54 "
"8f c5 6c ae 25 5b 4b 17 02 9c 4a 24 40 e5 9e 22 c6 49 62 b6 6b bb a8 cc e8 81 50 47 c8 be 5c a4 "
"d6 94 4f 7b 9a cf e4 59 7a a1 ea 31 37 13 2d af 21 69 19 1d 6f 16 98 1e 08 e3 b2 4d 9b 7f a9 77 "
"ed bd d4 d9 34 d3 ca 09 18 60 c9 6a 01 f4 f6 64 b4 3a 15 ac 89 52 68 71 e7 82 c1 0c 92 f7 30 e6 "
"1c 3e 0f 0a 67 35 ba 61 dd 29 c2 f8 97 95 b7 3b e0 ce f9 d5 06 76 b3 05 4c 04 84 3c 87 23 63 7c "
"53 56 e1 7d 96 1b d1 ec 2a 66 f1 11 10 ff 43 2e df 83 74 f5 38 20 fd ad c4 b9 55 51 b0 ef 00 57";

static const char *S_A16_2 =
"00 b8 f0 34 ca 21 3c f9 01 8e 75 70 ec 13 27 96 f4 5b 88 1f eb 4a 7d 9d be 02 14 af a2 06 c6 db "
"35 6b 74 45 7b 29 d2 fe b6 15 d0 8a a9 2d 19 f6 5e 5a 90 e9 11 33 c2 47 37 4c 4f 59 c3 04 57 1d "
"f2 63 6d 6e 31 95 cb 3e 67 b2 e3 98 ed 8d e6 fb f8 ba 5d d4 2a f5 3b 82 05 16 44 ef 4d e7 93 da "
"9f bb 61 c9 53 bd 76 78 52 36 0c 66 c1 10 dd 7a 84 69 cd fd 58 0d 6c 89 68 ad 3a b0 4b 46 c5 03 "
"b4 f7 30 8c 4e 60 73 a1 8b b1 62 cc d1 08 fc 77 7e cf 56 51 07 a6 80 92 dc 0b a4 c7 e8 e1 b5 71 "
"ea b3 2f 94 18 e2 3d 49 65 aa f1 91 c8 99 55 79 86 a7 26 a0 ac 5f ce 6a 5c f3 87 8f 12 1c d8 e4 "
"9b 64 2e 1e d7 c0 17 bc a3 a8 9a 0e 25 40 41 50 b9 bf 28 df 32 54 9e 48 d5 2b 42 fa 9c 7f d3 85 "
"43 de 81 0f 24 c4 38 ae 83 1b 6f 7c e5 ff 1a d9 3f b7 22 97 09 e0 a5 20 23 2c 72 d6 39 ab 0a ee";

static const char *S_A0 =
"26 48 06 9b 21 a9 1b 76 c9 f8 b4 67 e4 ff 99 f7 15 9e 62 00 72 4d a0 4f 02 f1 ea ef 0b f3 eb a6 "
"93 78 6f 7c da d4 7b 05 e9 c6 d6 db 50 ce d2 01 b5 e8 e0 2a 08 1a b8 e3 f9 b1 f4 8b 39 2d 85 9c "
"55 73 63 40 38 96 dc a3 a2 a1 25 66 6d 56 8e 10 0f 31 1c f5 28 77 0a d1 75 34 a4 fe 7d 07 51 79 "
"41 90 22 35 12 bb c4 ca b2 1f cb c8 ac dd d0 0d fc c5 9d 14 bc 83 d9 58 c2 30 9a 6a c0 0c ad f6 "
"5d 74 7f 2f bd 1d 47 d5 e6 89 cf b7 d3 59 36 98 f0 fb 3c f2 3f a7 18 82 42 5c ab ba de 52 09 91 "
"aa 61 ec d7 95 23 cd 80 a5 68 60 27 71 e1 2c 2e 8d 2b 57 65 bf c1 19 c7 49 64 88 4a cc 20 4e d8 "
"3b 4c 13 5f 9f be 5e 6e fd e2 fa 54 37 0e 16 7a 6c 33 b3 70 84 7e c3 04 b0 ae b9 81 03 29 df 46 "
"e5 69 e7 24 92 5a 4b 5b 94 11 3a 3d 87 ed 97 b6 32 3e 45 af 1e 43 44 8c 53 86 6b ee a8 8a 8f 17";

static void parse(const char *s, u8 *d, const char *name)
{
    for (int i = 0; i < 256; i++) {
        unsigned v; int n;
        if (sscanf(s, "%x%n", &v, &n) != 1) { fprintf(stderr, "table %s: parse error at %d\n", name, i); exit(1); }
        d[i] = (u8)v; s += n;
    }
    { unsigned dummy; if (sscanf(s, "%x", &dummy) == 1) { fprintf(stderr, "table %s: too many entries\n", name); exit(1); } }
}

static int is_perm(const u8 *t)
{
    int seen[256] = {0};
    for (int i = 0; i < 256; i++) seen[t[i]]++;
    for (int i = 0; i < 256; i++) if (seen[i] != 1) return 0;
    return 1;
}

static void init_tables(int verbose)
{
    parse(S_T0_03, T0_03, "T0_03"); parse(S_T0_12, T0_12, "T0_12");
    parse(S_T1_03, T1_03, "T1_03"); parse(S_T1_12, T1_12, "T1_12");
    parse(S_A8_1, A8_1, "A8_1");    parse(S_A8_2, A8_2, "A8_2");
    parse(S_A16_1, A16_1, "A16_1"); parse(S_A16_2, A16_2, "A16_2");
    parse(S_A0, A0, "A0");
    if (verbose) {
        const char *nm[9] = {"T0_03","T0_12","T1_03","T1_12","A8_1","A8_2","A16_1","A16_2","A0"};
        const u8 *tb[9] = {T0_03,T0_12,T1_03,T1_12,A8_1,A8_2,A16_1,A16_2,A0};
        for (int i = 0; i < 9; i++) printf("table %-6s permutation check: %s\n", nm[i], is_perm(tb[i]) ? "OK" : "NOT a permutation (check transcription)");
    }
}

/* ---------- bit helpers (PCB scramble) ---------- */
static const int bs32[32] = {0x09,0x0d,0x13,0x00,0x17,0x0f,0x03,0x05,0x04,0x0c,0x11,0x1e,0x12,0x15,0x0b,0x06,
                             0x1b,0x0a,0x1a,0x1c,0x14,0x02,0x0e,0x1d,0x18,0x08,0x01,0x10,0x19,0x1f,0x07,0x16};
static const int bs24[24] = {0x17,0x16,0x15,0x04,0x0b,0x0e,0x08,0x0c,0x10,0x00,0x0a,0x13,
                             0x03,0x06,0x02,0x07,0x0d,0x01,0x11,0x09,0x14,0x0f,0x12,0x05};
static const u8 xorval[4] = {0x34, 0x21, 0xc4, 0xe9};

static u32 lutF[4][256], lutI[4][256], lutO[3][256];
static u8 finv[256];

static u8 s1_fwd(u8 x) /* bitswap<8>(x ^ 0xd2, 4,0,7,2,5,1,6,3) */
{
    u8 v = x ^ 0xd2;
    static const int o[8] = {4,0,7,2,5,1,6,3};
    u8 r = 0;
    for (int k = 0; k < 8; k++) r |= ((v >> o[k]) & 1) << (7 - k);
    return r;
}

static void init_luts(void)
{
    for (int b = 0; b < 4; b++)
        for (int x = 0; x < 256; x++) {
            u32 v = (u32)x << (8 * b), f = 0, r = 0;
            for (int k = 0; k < 32; k++) { f |= ((v >> bs32[k]) & 1u) << (31 - k); r |= ((v >> (31 - k)) & 1u) << bs32[k]; }
            lutF[b][x] = f; lutI[b][x] = r;
        }
    for (int b = 0; b < 3; b++)
        for (int x = 0; x < 256; x++) {
            u32 v = ((u32)x << (8 * b)) & 0x1fffff, r = 0;
            for (int k = 0; k < 24; k++) r |= ((v >> bs24[k]) & 1u) << (23 - k);
            lutO[b][x] = r;
        }
    for (int x = 0; x < 256; x++) finv[s1_fwd((u8)x)] = (u8)x;
}

static inline u32 ld32(const u8 *p) { return p[0] | p[1] << 8 | p[2] << 16 | (u32)p[3] << 24; }
static inline void st32(u8 *p, u32 v) { p[0] = v; p[1] = v >> 8; p[2] = v >> 16; p[3] = v >> 24; }
static inline u32 bsF(u32 v) { return lutF[0][v & 255] | lutF[1][(v >> 8) & 255] | lutF[2][(v >> 16) & 255] | lutF[3][v >> 24]; }
static inline u32 bsI(u32 v) { return lutI[0][v & 255] | lutI[1][(v >> 8) & 255] | lutI[2][(v >> 16) & 255] | lutI[3][v >> 24]; }

static inline u32 pcb_ofst(u32 i) /* dword index -> source dword index (MAME) */
{
    u32 m = i & 0x1fffff;
    u32 o = lutO[0][m & 255] | lutO[1][(m >> 8) & 255] | lutO[2][(m >> 16) & 255];
    o ^= 0x0c8923;
    return o + (i & 0xffe00000);
}

/* MAME svcpcb_gfx_decrypt (used for self-test) */
static void pcb_decrypt(u8 *rom, size_t size)
{
    u8 *buf = malloc(size);
    for (size_t i = 0; i < size; i++) rom[i] ^= xorval[i & 3];
    for (size_t i = 0; i < size; i += 4) st32(buf + i, bsF(ld32(rom + i)));
    for (size_t i = 0; i < size / 4; i++) memcpy(rom + i * 4, buf + (size_t)pcb_ofst((u32)i) * 4, 4);
    free(buf);
}

/* inverse of the above */
static void pcb_encrypt(u8 *rom, size_t size)
{
    u8 *buf = malloc(size);
    for (size_t i = 0; i < size / 4; i++) memcpy(buf + (size_t)pcb_ofst((u32)i) * 4, rom + i * 4, 4);
    for (size_t i = 0; i < size; i += 4) st32(rom + i, bsI(ld32(buf + i)));
    for (size_t i = 0; i < size; i++) rom[i] ^= xorval[i & 3];
    free(buf);
}

/* ---------- CMC50 ---------- */
typedef struct { u8 xa0, xa1, xb0, xb1; int inva, invb; } DP;

static inline DP dparams(u32 r)
{
    DP d; u32 hi = (r >> 8) & 0xff; u8 a0 = A0[hi], tmp;
    tmp = T1_03[(r & 0xff) ^ a0];
    d.xa0 = (T0_03[hi] & 0xfe) | (tmp & 1);
    d.xa1 = (tmp & 0xfe) | (T0_12[hi] & 1);
    d.inva = (r >> 8) & 1;
    tmp = T1_12[(r & 0xff) ^ a0];
    d.xb0 = (T0_12[hi] & 0xfe) | (tmp & 1);
    d.xb1 = (tmp & 0xfe) | (T0_03[hi] & 1);
    d.invb = ((r >> 16) ^ A16_2[hi]) & 1;
    return d;
}

static inline u32 cmc_addr(u32 rpos, u32 key, u32 mask)
{
    u32 b = rpos ^ key;
    b ^= (u32)A8_1[(b >> 16) & 0xff] << 8;
    b ^= (u32)A8_2[b & 0xff] << 8;
    b ^= (u32)A16_1[b & 0xff] << 16;
    b ^= (u32)A16_2[(b >> 8) & 0xff] << 16;
    b ^= A0[(b >> 8) & 0xff];
    return b & mask;
}

/* MAME cmc50_gfx_decrypt (used for self-test) */
static void cmc_decrypt(u8 *rom, size_t size, u32 key)
{
    size_t n = size / 4; u32 mask = (u32)n - 1;
    u8 *buf = malloc(size);
    for (size_t q = 0; q < n; q++) {
        DP d = dparams((u32)q); const u8 *c = rom + q * 4; u8 *b = buf + q * 4;
        if (!d.inva) { b[0] = c[0] ^ d.xa0; b[3] = c[3] ^ d.xa1; } else { b[0] = c[3] ^ d.xa0; b[3] = c[0] ^ d.xa1; }
        if (!d.invb) { b[1] = c[1] ^ d.xb0; b[2] = c[2] ^ d.xb1; } else { b[1] = c[2] ^ d.xb0; b[2] = c[1] ^ d.xb1; }
    }
    for (size_t r = 0; r < n; r++) memcpy(rom + r * 4, buf + (size_t)cmc_addr((u32)r, key, mask) * 4, 4);
    free(buf);
}

/* inverse of cmc_decrypt */
static void cmc_encrypt(u8 *rom, size_t size, u32 key)
{
    size_t n = size / 4; u32 mask = (u32)n - 1;
    u8 *buf = malloc(size);
    for (size_t r = 0; r < n; r++) memcpy(buf + (size_t)cmc_addr((u32)r, key, mask) * 4, rom + r * 4, 4);
    for (size_t q = 0; q < n; q++) {
        DP d = dparams((u32)q); const u8 *b = buf + q * 4; u8 *c = rom + q * 4;
        if (!d.inva) { c[0] = b[0] ^ d.xa0; c[3] = b[3] ^ d.xa1; } else { c[3] = b[0] ^ d.xa0; c[0] = b[3] ^ d.xa1; }
        if (!d.invb) { c[1] = b[1] ^ d.xb0; c[2] = b[2] ^ d.xb1; } else { c[2] = b[1] ^ d.xb0; c[1] = b[2] ^ d.xb1; }
    }
    free(buf);
}

/* ---------- misc ---------- */
static u32 crc_tab[256];
static void crc_init(void) { for (u32 i = 0; i < 256; i++) { u32 c = i; for (int k = 0; k < 8; k++) c = c & 1 ? 0xedb88320u ^ (c >> 1) : c >> 1; crc_tab[i] = c; } }
static u32 crc32b(const u8 *p, size_t n) { u32 c = 0xffffffffu; while (n--) c = crc_tab[(c ^ *p++) & 255] ^ (c >> 8); return ~c; }

static int write_file(const char *name, const u8 *p, size_t n)
{
    FILE *f = fopen(name, "wb");
    if (!f) { perror(name); return 0; }
    if (fwrite(p, 1, n, f) != n) { perror(name); fclose(f); return 0; }
    fclose(f);
    printf("  %-16s %9zu bytes  CRC32 %08x\n", name, n, crc32b(p, n));
    return 1;
}

static u8 *read_file(const char *name, size_t expect)
{
    FILE *f = fopen(name, "rb");
    if (!f) { perror(name); return NULL; }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if ((size_t)sz != expect) { fprintf(stderr, "%s: size %ld, expected %zu\n", name, sz, expect); fclose(f); return NULL; }
    u8 *p = malloc(expect);
    if (fread(p, 1, expect, f) != expect) { perror(name); fclose(f); free(p); return NULL; }
    fclose(f);
    return p;
}

static int selftest(u32 key)
{
    init_tables(1);
    int ok = 1;
    /* address bijection */
    u8 *seen = calloc(1u << 24, 1);
    u32 dup = 0;
    for (u32 r = 0; r < (1u << 24); r++) { u32 a = cmc_addr(r, key, 0xffffff); if (seen[a]) dup++; seen[a] = 1; }
    free(seen);
    printf("cmc address map bijective: %s\n", dup ? "NO" : "yes");
    if (dup) ok = 0;
    for (int x = 0; x < 256; x++) if (s1_fwd(finv[s1_fwd((u8)x)]) != s1_fwd((u8)x)) ok = 0;

    u8 *orig = malloc(SPR_SIZE), *w = malloc(SPR_SIZE);
    u32 s = 0x12345678;
    for (size_t i = 0; i < SPR_SIZE; i++) { s ^= s << 13; s ^= s >> 17; s ^= s << 5; orig[i] = (u8)(s >> 11); }
    memcpy(w, orig, SPR_SIZE);
    cmc_encrypt(w, SPR_SIZE, key);
    pcb_encrypt(w, SPR_SIZE);
    pcb_decrypt(w, SPR_SIZE);
    cmc_decrypt(w, SPR_SIZE, key);
    int same = memcmp(orig, w, SPR_SIZE) == 0;
    printf("round trip (encrypt -> MAME-style decrypt): %s\n", same ? "MATCH" : "MISMATCH");
    if (!same) ok = 0;
    free(orig); free(w);
    printf("selftest: %s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}

static void usage(void)
{
    puts("svcenc - SVC Chaos plaintext C-ROM -> JAMMA PCB encrypted C-ROM\n"
         "\n"
         "  svcenc selftest [-k KEY]\n"
         "  (use -g ms5 for Metal Slug 5; default is svc)\n"
         "  svcenc enc [options] region.bin            (64MB plaintext, MAME sprite-region layout)\n"
         "  svcenc enc [options] c1 c2 c3 c4 c5 c6 c7 c8   (8 x 8MB MVS-style plaintext, c1/c2 byte-interleaved ...)\n"
         "\n"
         "options:\n"
         "  -g GAME    svc (default; key 57, S tail 0x80000) or ms5 (key 19, S tail 0x20000)\n"
         "  -k HEX     override CMC50 extra xor key\n"
         "  -f FMT     output: word32 (4 x 16MB, svcpcba/MS5-style, default)\n"
         "                     linear (2 x 32MB, svcpcb)\n"
         "                     raw    (1 x 64MB)\n"
         "  -n         do not convert the S-data tail (last 0x80000 bytes)\n");
}

int main(int argc, char **argv)
{
    u32 key = 0x57; int fmt = 0, notail = 0, ms5 = 0, keyset = 0;
    if (argc < 2) { usage(); return 1; }
    crc_init(); init_luts();
    const char *cmd = argv[1];
    char *files[16]; int nf = 0;
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "-k") && i + 1 < argc) { key = (u32)strtoul(argv[++i], NULL, 16); keyset = 1; }
        else if (!strcmp(argv[i], "-g") && i + 1 < argc) { const char *g = argv[++i]; if (!strcmp(g, "ms5")) ms5 = 1; else if (strcmp(g, "svc")) { usage(); return 1; } }
        else if (!strcmp(argv[i], "-f") && i + 1 < argc) {
            const char *f = argv[++i];
            fmt = !strcmp(f, "word32") ? 0 : !strcmp(f, "linear") ? 1 : !strcmp(f, "raw") ? 2 : -1;
            if (fmt < 0) { usage(); return 1; }
        } else if (!strcmp(argv[i], "-n")) notail = 1;
        else if (nf < 16) files[nf++] = argv[i];
    }
    if (ms5) { if (!keyset) key = 0x19; TAIL_SIZE = 0x20000u; if (fmt == 1) { fprintf(stderr, "ms5: -f linear is not defined for ms5pcb; use word32\n"); return 1; } }
    if (!strcmp(cmd, "selftest")) return selftest(key);
    if (strcmp(cmd, "enc") || (nf != 1 && nf != 8)) { usage(); return 1; }

    init_tables(0);
    u8 *rom = NULL;
    if (nf == 1) {
        rom = read_file(files[0], SPR_SIZE);
        if (!rom) return 1;
    } else {
        rom = malloc(SPR_SIZE);
        for (int p = 0; p < 4; p++) {
            u8 *a = read_file(files[p * 2], 0x800000), *b = read_file(files[p * 2 + 1], 0x800000);
            if (!a || !b) return 1;
            u8 *d = rom + (size_t)p * 0x1000000;
            for (size_t k = 0; k < 0x800000; k++) { d[2 * k] = a[k]; d[2 * k + 1] = b[k]; }
            free(a); free(b);
        }
    }
    printf("game = %s, key = %02x, tail = 0x%x, tail conversion = %s\n", ms5 ? "ms5" : "svc", key, TAIL_SIZE, notail ? "off" : "on");

    if (!notail)
        for (size_t i = SPR_SIZE - TAIL_SIZE; i < SPR_SIZE; i++) rom[i] = finv[rom[i]];

    cmc_encrypt(rom, SPR_SIZE, key);
    pcb_encrypt(rom, SPR_SIZE);

    puts("output:");
    if (fmt == 2) return !write_file("svc_c_pcb.bin", rom, SPR_SIZE);
    if (fmt == 1) {
        return !(write_file("269-c1.c1", rom, 0x2000000) && write_file("269-c2.c2", rom + 0x2000000, 0x2000000));
    }
    static const char *nm_svc[4] = {"269-c1a.c1", "269-c2a.c2", "269-c3a.c3", "269-c4a.c4"};
    static const char *nm_ms5[4] = {"268-c1.c1", "268-c2.c2", "268-c3.c3", "268-c4.c4"};
    const char **nm = ms5 ? nm_ms5 : nm_svc;
    u8 *o = malloc(0x1000000);
    for (int c = 0; c < 4; c++) {
        const u8 *base = rom + (c >> 1) * 0x2000000u;
        int lane = (c & 1) * 2;
        for (size_t j = 0; j < 0x800000; j++) { o[2 * j] = base[4 * j + lane]; o[2 * j + 1] = base[4 * j + lane + 1]; }
        if (!write_file(nm[c], o, 0x1000000)) return 1;
    }
    return 0;
}