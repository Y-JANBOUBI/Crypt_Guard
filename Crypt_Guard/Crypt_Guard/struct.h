

//========================================================================================================================================//
// Include
//========================================================================================================================================//
#pragma once
#include <windows.h>
#include <stdint.h> 
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#pragma comment(lib, "Advapi32.lib")
#pragma execution_character_set("utf-8")



//========================================================================================================================================//
// Heder
//========================================================================================================================================//
#define KEY_SIZE 0x20
#define IV_SIZE 0x10
#define MAX_DISPLAY_BYTES 64 
#define	HEDER_NAME	"heder.h"

#define ALLOC(SIZE) LocalAlloc(LPTR, (SIZE_T)SIZE)
#define FREE(BUFF) LocalFree((LPVOID)BUFF)
#define REALLOC(BUFF, SIZE) LocalReAlloc(BUFF, SIZE, LMEM_MOVEABLE | LMEM_ZEROINIT)


typedef struct {
    uint16_t slice[8];
} AES_state;
typedef struct {
    AES_state rk[15];
} AES256_ctx;
typedef struct {
    AES256_ctx ctx;
    uint8_t iv[16];
} AES256_CBC_ctx;

void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv);
boolean AES256_CBC_encrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* plain, IN size_t plainsize, OUT PBYTE* encrypted);
boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain);

static void LoadByte(AES_state* s, unsigned char byte, int r, int c) {
    int i;
    for (i = 0; i < 8; i++) {
        s->slice[i] |= (uint16_t)(byte & 1) << (r * 4 + c);
        byte >>= 1;
    }
}
static void LoadBytes(AES_state* s, const unsigned char* data16) {
    int c;
    for (c = 0; c < 4; c++) {
        int r;
        for (r = 0; r < 4; r++) {
            LoadByte(s, *(data16++), r, c);
        }
    }
}
static void SaveBytes(unsigned char* data16, const AES_state* s) {
    int c;
    for (c = 0; c < 4; c++) {
        int r;
        for (r = 0; r < 4; r++) {
            int b;
            uint8_t v = 0;
            for (b = 0; b < 8; b++) {
                v |= ((s->slice[b] >> (r * 4 + c)) & 1) << b;
            }
            *(data16++) = v;
        }
    }
}
static void SubBytes(AES_state* s, int inv) {
    uint16_t U0 = s->slice[7], U1 = s->slice[6], U2 = s->slice[5], U3 = s->slice[4];
    uint16_t U4 = s->slice[3], U5 = s->slice[2], U6 = s->slice[1], U7 = s->slice[0];

    uint16_t T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16;
    uint16_t T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, D;
    uint16_t M1, M6, M11, M13, M15, M20, M21, M22, M23, M25, M37, M38, M39, M40;
    uint16_t M41, M42, M43, M44, M45, M46, M47, M48, M49, M50, M51, M52, M53, M54;
    uint16_t M55, M56, M57, M58, M59, M60, M61, M62, M63;

    if (inv) {
        uint16_t R5, R13, R17, R18, R19;

        T23 = U0 ^ U3;
        T22 = ~(U1 ^ U3);
        T2 = ~(U0 ^ U1);
        T1 = U3 ^ U4;
        T24 = ~(U4 ^ U7);
        R5 = U6 ^ U7;
        T8 = ~(U1 ^ T23);
        T19 = T22 ^ R5;
        T9 = ~(U7 ^ T1);
        T10 = T2 ^ T24;
        T13 = T2 ^ R5;
        T3 = T1 ^ R5;
        T25 = ~(U2 ^ T1);
        R13 = U1 ^ U6;
        T17 = ~(U2 ^ T19);
        T20 = T24 ^ R13;
        T4 = U4 ^ T8;
        R17 = ~(U2 ^ U5);
        R18 = ~(U5 ^ U6);
        R19 = ~(U2 ^ U4);
        D = U0 ^ R17;
        T6 = T22 ^ R17;
        T16 = R13 ^ R19;
        T27 = T1 ^ R18;
        T15 = T10 ^ T27;
        T14 = T10 ^ R18;
        T26 = T3 ^ T16;
    }
    else {

        T1 = U0 ^ U3;
        T2 = U0 ^ U5;
        T3 = U0 ^ U6;
        T4 = U3 ^ U5;
        T5 = U4 ^ U6;
        T6 = T1 ^ T5;
        T7 = U1 ^ U2;
        T8 = U7 ^ T6;
        T9 = U7 ^ T7;
        T10 = T6 ^ T7;
        T11 = U1 ^ U5;
        T12 = U2 ^ U5;
        T13 = T3 ^ T4;
        T14 = T6 ^ T11;
        T15 = T5 ^ T11;
        T16 = T5 ^ T12;
        T17 = T9 ^ T16;
        T18 = U3 ^ U7;
        T19 = T7 ^ T18;
        T20 = T1 ^ T19;
        T21 = U6 ^ U7;
        T22 = T7 ^ T21;
        T23 = T2 ^ T22;
        T24 = T2 ^ T10;
        T25 = T20 ^ T17;
        T26 = T3 ^ T16;
        T27 = T1 ^ T12;
        D = U7;
    }


    M1 = T13 & T6;
    M6 = T3 & T16;
    M11 = T1 & T15;
    M13 = (T4 & T27) ^ M11;
    M15 = (T2 & T10) ^ M11;
    M20 = T14 ^ M1 ^ (T23 & T8) ^ M13;
    M21 = (T19 & D) ^ M1 ^ T24 ^ M15;
    M22 = T26 ^ M6 ^ (T22 & T9) ^ M13;
    M23 = (T20 & T17) ^ M6 ^ M15 ^ T25;
    M25 = M22 & M20;
    M37 = M21 ^ ((M20 ^ M21) & (M23 ^ M25));
    M38 = M20 ^ M25 ^ (M21 | (M20 & M23));
    M39 = M23 ^ ((M22 ^ M23) & (M21 ^ M25));
    M40 = M22 ^ M25 ^ (M23 | (M21 & M22));
    M41 = M38 ^ M40;
    M42 = M37 ^ M39;
    M43 = M37 ^ M38;
    M44 = M39 ^ M40;
    M45 = M42 ^ M41;
    M46 = M44 & T6;
    M47 = M40 & T8;
    M48 = M39 & D;
    M49 = M43 & T16;
    M50 = M38 & T9;
    M51 = M37 & T17;
    M52 = M42 & T15;
    M53 = M45 & T27;
    M54 = M41 & T10;
    M55 = M44 & T13;
    M56 = M40 & T23;
    M57 = M39 & T19;
    M58 = M43 & T3;
    M59 = M38 & T22;
    M60 = M37 & T20;
    M61 = M42 & T1;
    M62 = M45 & T4;
    M63 = M41 & T2;

    if (inv) {

        uint16_t P0 = M52 ^ M61;
        uint16_t P1 = M58 ^ M59;
        uint16_t P2 = M54 ^ M62;
        uint16_t P3 = M47 ^ M50;
        uint16_t P4 = M48 ^ M56;
        uint16_t P5 = M46 ^ M51;
        uint16_t P6 = M49 ^ M60;
        uint16_t P7 = P0 ^ P1;
        uint16_t P8 = M50 ^ M53;
        uint16_t P9 = M55 ^ M63;
        uint16_t P10 = M57 ^ P4;
        uint16_t P11 = P0 ^ P3;
        uint16_t P12 = M46 ^ M48;
        uint16_t P13 = M49 ^ M51;
        uint16_t P14 = M49 ^ M62;
        uint16_t P15 = M54 ^ M59;
        uint16_t P16 = M57 ^ M61;
        uint16_t P17 = M58 ^ P2;
        uint16_t P18 = M63 ^ P5;
        uint16_t P19 = P2 ^ P3;
        uint16_t P20 = P4 ^ P6;
        uint16_t P22 = P2 ^ P7;
        uint16_t P23 = P7 ^ P8;
        uint16_t P24 = P5 ^ P7;
        uint16_t P25 = P6 ^ P10;
        uint16_t P26 = P9 ^ P11;
        uint16_t P27 = P10 ^ P18;
        uint16_t P28 = P11 ^ P25;
        uint16_t P29 = P15 ^ P20;
        s->slice[7] = P13 ^ P22;
        s->slice[6] = P26 ^ P29;
        s->slice[5] = P17 ^ P28;
        s->slice[4] = P12 ^ P22;
        s->slice[3] = P23 ^ P27;
        s->slice[2] = P19 ^ P24;
        s->slice[1] = P14 ^ P23;
        s->slice[0] = P9 ^ P16;
    }
    else {

        uint16_t L0 = M61 ^ M62;
        uint16_t L1 = M50 ^ M56;
        uint16_t L2 = M46 ^ M48;
        uint16_t L3 = M47 ^ M55;
        uint16_t L4 = M54 ^ M58;
        uint16_t L5 = M49 ^ M61;
        uint16_t L6 = M62 ^ L5;
        uint16_t L7 = M46 ^ L3;
        uint16_t L8 = M51 ^ M59;
        uint16_t L9 = M52 ^ M53;
        uint16_t L10 = M53 ^ L4;
        uint16_t L11 = M60 ^ L2;
        uint16_t L12 = M48 ^ M51;
        uint16_t L13 = M50 ^ L0;
        uint16_t L14 = M52 ^ M61;
        uint16_t L15 = M55 ^ L1;
        uint16_t L16 = M56 ^ L0;
        uint16_t L17 = M57 ^ L1;
        uint16_t L18 = M58 ^ L8;
        uint16_t L19 = M63 ^ L4;
        uint16_t L20 = L0 ^ L1;
        uint16_t L21 = L1 ^ L7;
        uint16_t L22 = L3 ^ L12;
        uint16_t L23 = L18 ^ L2;
        uint16_t L24 = L15 ^ L9;
        uint16_t L25 = L6 ^ L10;
        uint16_t L26 = L7 ^ L9;
        uint16_t L27 = L8 ^ L10;
        uint16_t L28 = L11 ^ L14;
        uint16_t L29 = L11 ^ L17;
        s->slice[7] = L6 ^ L24;
        s->slice[6] = ~(L16 ^ L26);
        s->slice[5] = ~(L19 ^ L28);
        s->slice[4] = L6 ^ L21;
        s->slice[3] = L20 ^ L22;
        s->slice[2] = L25 ^ L29;
        s->slice[1] = ~(L13 ^ L27);
        s->slice[0] = ~(L6 ^ L23);
    }
}

#define BIT_RANGE(from,to) ((uint16_t)((1 << ((to) - (from))) - 1) << (from))
#define BIT_RANGE_LEFT(x,from,to,shift) (((x) & BIT_RANGE((from), (to))) << (shift))
#define BIT_RANGE_RIGHT(x,from,to,shift) (((x) & BIT_RANGE((from), (to))) >> (shift))
#define ROT(x,b) (((x) >> ((b) * 4)) | ((x) << ((4-(b)) * 4)))

static void ShiftRows(AES_state* s) {
    int i;
    for (i = 0; i < 8; i++) {
        uint16_t v = s->slice[i];
        s->slice[i] =
            (v & BIT_RANGE(0, 4)) |
            BIT_RANGE_LEFT(v, 4, 5, 3) | BIT_RANGE_RIGHT(v, 5, 8, 1) |
            BIT_RANGE_LEFT(v, 8, 10, 2) | BIT_RANGE_RIGHT(v, 10, 12, 2) |
            BIT_RANGE_LEFT(v, 12, 15, 1) | BIT_RANGE_RIGHT(v, 15, 16, 3);
    }
}
static void InvShiftRows(AES_state* s) {
    int i;
    for (i = 0; i < 8; i++) {
        uint16_t v = s->slice[i];
        s->slice[i] =
            (v & BIT_RANGE(0, 4)) |
            BIT_RANGE_LEFT(v, 4, 7, 1) | BIT_RANGE_RIGHT(v, 7, 8, 3) |
            BIT_RANGE_LEFT(v, 8, 10, 2) | BIT_RANGE_RIGHT(v, 10, 12, 2) |
            BIT_RANGE_LEFT(v, 12, 13, 3) | BIT_RANGE_RIGHT(v, 13, 16, 1);
    }
}
static void MixColumns(AES_state* s, int inv) {

    uint16_t s0 = s->slice[0], s1 = s->slice[1], s2 = s->slice[2], s3 = s->slice[3];
    uint16_t s4 = s->slice[4], s5 = s->slice[5], s6 = s->slice[6], s7 = s->slice[7];
    uint16_t s0_01 = s0 ^ ROT(s0, 1), s0_123 = ROT(s0_01, 1) ^ ROT(s0, 3);
    uint16_t s1_01 = s1 ^ ROT(s1, 1), s1_123 = ROT(s1_01, 1) ^ ROT(s1, 3);
    uint16_t s2_01 = s2 ^ ROT(s2, 1), s2_123 = ROT(s2_01, 1) ^ ROT(s2, 3);
    uint16_t s3_01 = s3 ^ ROT(s3, 1), s3_123 = ROT(s3_01, 1) ^ ROT(s3, 3);
    uint16_t s4_01 = s4 ^ ROT(s4, 1), s4_123 = ROT(s4_01, 1) ^ ROT(s4, 3);
    uint16_t s5_01 = s5 ^ ROT(s5, 1), s5_123 = ROT(s5_01, 1) ^ ROT(s5, 3);
    uint16_t s6_01 = s6 ^ ROT(s6, 1), s6_123 = ROT(s6_01, 1) ^ ROT(s6, 3);
    uint16_t s7_01 = s7 ^ ROT(s7, 1), s7_123 = ROT(s7_01, 1) ^ ROT(s7, 3);

    s->slice[0] = s7_01 ^ s0_123;
    s->slice[1] = s7_01 ^ s0_01 ^ s1_123;
    s->slice[2] = s1_01 ^ s2_123;
    s->slice[3] = s7_01 ^ s2_01 ^ s3_123;
    s->slice[4] = s7_01 ^ s3_01 ^ s4_123;
    s->slice[5] = s4_01 ^ s5_123;
    s->slice[6] = s5_01 ^ s6_123;
    s->slice[7] = s6_01 ^ s7_123;
    if (inv) {

        uint16_t t0_02 = s->slice[0] ^ ROT(s->slice[0], 2);
        uint16_t t1_02 = s->slice[1] ^ ROT(s->slice[1], 2);
        uint16_t t2_02 = s->slice[2] ^ ROT(s->slice[2], 2);
        uint16_t t3_02 = s->slice[3] ^ ROT(s->slice[3], 2);
        uint16_t t4_02 = s->slice[4] ^ ROT(s->slice[4], 2);
        uint16_t t5_02 = s->slice[5] ^ ROT(s->slice[5], 2);
        uint16_t t6_02 = s->slice[6] ^ ROT(s->slice[6], 2);
        uint16_t t7_02 = s->slice[7] ^ ROT(s->slice[7], 2);

        s->slice[0] ^= t6_02;
        s->slice[1] ^= t6_02 ^ t7_02;
        s->slice[2] ^= t0_02 ^ t7_02;
        s->slice[3] ^= t1_02 ^ t6_02;
        s->slice[4] ^= t2_02 ^ t6_02 ^ t7_02;
        s->slice[5] ^= t3_02 ^ t7_02;
        s->slice[6] ^= t4_02;
        s->slice[7] ^= t5_02;
    }
}
static void AddRoundKey(AES_state* s, const AES_state* round) {
    int b;
    for (b = 0; b < 8; b++) {
        s->slice[b] ^= round->slice[b];
    }
}
static void GetOneColumn(AES_state* s, const AES_state* a, int c) {
    int b;
    for (b = 0; b < 8; b++) {
        s->slice[b] = (a->slice[b] >> c) & 0x1111;
    }
}
static void KeySetupColumnMix(AES_state* s, AES_state* r, const AES_state* a, int c1, int c2) {
    int b;
    for (b = 0; b < 8; b++) {
        r->slice[b] |= ((s->slice[b] ^= ((a->slice[b] >> c2) & 0x1111)) & 0x1111) << c1;
    }
}
static void KeySetupTransform(AES_state* s, const AES_state* r) {
    int b;
    for (b = 0; b < 8; b++) {
        s->slice[b] = ((s->slice[b] >> 4) | (s->slice[b] << 12)) ^ r->slice[b];
    }
}
static void MultX(AES_state* s) {
    uint16_t top = s->slice[7];
    s->slice[7] = s->slice[6];
    s->slice[6] = s->slice[5];
    s->slice[5] = s->slice[4];
    s->slice[4] = s->slice[3] ^ top;
    s->slice[3] = s->slice[2] ^ top;
    s->slice[2] = s->slice[1];
    s->slice[1] = s->slice[0] ^ top;
    s->slice[0] = top;
}
static void AES_setup(AES_state* rounds, const uint8_t* key, int nkeywords, int nrounds)
{
    int i;

    AES_state rcon = { {1,0,0,0,0,0,0,0} };
    int pos = 0;
    AES_state column;

    for (i = 0; i < nrounds + 1; i++) {
        int b;
        for (b = 0; b < 8; b++) {
            rounds[i].slice[b] = 0;
        }
    }

    for (i = 0; i < nkeywords; i++) {
        int r;
        for (r = 0; r < 4; r++) {
            LoadByte(&rounds[i >> 2], *(key++), r, i & 3);
        }
    }

    GetOneColumn(&column, &rounds[(nkeywords - 1) >> 2], (nkeywords - 1) & 3);

    for (i = nkeywords; i < 4 * (nrounds + 1); i++) {
        if (pos == 0) {
            SubBytes(&column, 0);
            KeySetupTransform(&column, &rcon);
            MultX(&rcon);
        }
        else if (nkeywords > 6 && pos == 4) {
            SubBytes(&column, 0);
        }
        if (++pos == nkeywords) pos = 0;
        KeySetupColumnMix(&column, &rounds[i >> 2], &rounds[(i - nkeywords) >> 2], i & 3, (i - nkeywords) & 3);
    }
}
static void AES_encrypt(const AES_state* rounds, int nrounds, unsigned char* cipher16, const unsigned char* plain16) {
    AES_state s = { {0} };
    int round;

    LoadBytes(&s, plain16);
    AddRoundKey(&s, rounds++);

    for (round = 1; round < nrounds; round++) {
        SubBytes(&s, 0);
        ShiftRows(&s);
        MixColumns(&s, 0);
        AddRoundKey(&s, rounds++);
    }

    SubBytes(&s, 0);
    ShiftRows(&s);
    AddRoundKey(&s, rounds);

    SaveBytes(cipher16, &s);
}
static void AES_decrypt(const AES_state* rounds, int nrounds, unsigned char* plain16, const unsigned char* cipher16) {

    AES_state s = { {0} };
    int round;

    rounds += nrounds;

    LoadBytes(&s, cipher16);
    AddRoundKey(&s, rounds--);

    for (round = 1; round < nrounds; round++) {
        InvShiftRows(&s);
        SubBytes(&s, 1);
        AddRoundKey(&s, rounds--);
        MixColumns(&s, 1);
    }

    InvShiftRows(&s);
    SubBytes(&s, 1);
    AddRoundKey(&s, rounds);

    SaveBytes(plain16, &s);
}
static void Xor128(uint8_t* buf1, const uint8_t* buf2) {
    size_t i;
    for (i = 0; i < 16; i++) {
        buf1[i] ^= buf2[i];
    }
}
static void AESCBC_encrypt(const AES_state* rounds, uint8_t* iv, int nk, size_t blocks, unsigned char* encrypted, const unsigned char* plain) {
    size_t i;
    unsigned char buf[16];

    for (i = 0; i < blocks; i++) {
        memcpy(buf, plain, 16);
        Xor128(buf, iv);
        AES_encrypt(rounds, nk, encrypted, buf);
        memcpy(iv, encrypted, 16);
        plain += 16;
        encrypted += 16;
    }
}
static void AESCBC_decrypt(const AES_state* rounds, uint8_t* iv, int nk, size_t blocks, unsigned char* plain, const unsigned char* encrypted) {
    size_t i;
    uint8_t next_iv[16];

    for (i = 0; i < blocks; i++) {
        memcpy(next_iv, encrypted, 16);
        AES_decrypt(rounds, nk, plain, encrypted);
        Xor128(plain, iv);
        memcpy(iv, next_iv, 16);
        plain += 16;
        encrypted += 16;
    }
}
void AES256_init(AES256_ctx* ctx, const unsigned char* key32) {
    AES_setup(ctx->rk, key32, 8, 14);
}
void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv)
{
    AES256_init(&(ctx->ctx), key16);
    memcpy(ctx->iv, iv, 16);
}
boolean AES256_CBC_encrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* plain, IN size_t plainsize, OUT PBYTE* encrypted)
{
    if (plainsize % 16 != 0)
        return FALSE;
    size_t blocks = plainsize / 16;
    *encrypted = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, plainsize);
    if (*encrypted != NULL)
        AESCBC_encrypt(ctx->ctx.rk, ctx->iv, 14, blocks, *encrypted, plain);
    else
        return FALSE;

    return TRUE;
}
boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain)
{
    if (ciphersize % 16 != 0)
        return FALSE;
    size_t blocks = ciphersize / 16;
    *plain = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciphersize);
    if (*plain != NULL)
        AESCBC_decrypt(ctx->ctx.rk, ctx->iv, 14, blocks, *plain, encrypted);
    else
        return FALSE;

    return TRUE;
}






//========================================================================================================================================//
// Output
//========================================================================================================================================//
BOOL OpenPayloadFile(IN const char* fileName, OUT PBYTE* ppPayloadData, OUT PDWORD pPayloadSize) {

    //open file.bin
    HANDLE hFile = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Failed to open the file");
        return FALSE;
    }

    //get size of file 
    DWORD fileSize = GetFileSize(hFile, NULL);


    //allocated buffer for file 
    PBYTE payload = (PBYTE)HeapAlloc(GetProcessHeap(), 0, fileSize);
    if (!payload) {
        printf("[!] Failed to allocated buffer\n");
        CloseHandle(hFile);
        return FALSE;
    }

    //read file to allocated buffer 
    DWORD bytesRead = 0;
    if (!ReadFile(hFile, payload, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        printf("[!] ReadFile FAILED With Error: %d\n", GetLastError());
        HeapFree(GetProcessHeap(), 0, payload);
        CloseHandle(hFile);
        return FALSE;
    }

    //cleanup 
    if (hFile)
        CloseHandle(hFile);

    *ppPayloadData = payload;
    *pPayloadSize = fileSize;
    return TRUE;
}
VOID PrintHex(LPCSTR Name, PBYTE Data, SIZE_T Size) {
    printf("unsigned char %s[] = {", Name);
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0) {
            printf("\n\t");
        }
        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
    }
    printf("};\n\n");
}
VOID generate_RC4_output(IN PBYTE payload, IN SIZE_T spayload, IN PBYTE key, IN SIZE_T skey, IN BYTE key_HintByte) {

    printf("\n\n#include <stdio.h>\n"
    "#include <windows.h>\n\n"
    "typedef struct {\n"
    "    DWORD Length; \n"
    "    DWORD MaximumLength; \n"
    "    PVOID Buffer; \n"
    "} USTRING; \n\n"
    "NTSTATUS(NTAPI * fnSystem032)(\n"
    "    struct USTRING* Img,\n"
    "    struct USTRING* Key\n"
    "    ); \n\n"
    "BOOL RC4_Guard(IN PBYTE data, IN DWORD sdata, IN PBYTE pKey, IN DWORD sKey, IN BYTE HintByte){\n"
    "   BYTE            b = 0;\n"
    "   INT             i = 0; \n"
    "   PBYTE           pRealKey = (PBYTE)malloc(sKey); \n"
    "   char sys32[] = { 'S','y','s','t','e','m','F','u','n','c','t','i','o','n','0','3','2','\\0'};\n"
    "   if (!pRealKey)\n"
    "       return FALSE; \n"
    "   while (1) {\n"
    "       if (((pKey[0] ^ b)) == HintByte)\n"
    "           break; \n"
    "       else\n"
    "           b++; \n"
    "   }\n"
    "   for (int i = 0; i < sKey; i++) {\n"
    "       pRealKey[i] = (BYTE)((pKey[i] ^ b) - i); \n"
    "   }\n\n"
    "   USTRING Key = { .Buffer = pRealKey, .Length = sKey, .MaximumLength = sKey }, \n"
    "       Img = { .Buffer = data, .Length = sdata, .MaximumLength = sdata }; \n"
    "   fnSystem032 = GetProcAddress(LoadLibraryA(\"Advapi32\"), sys32); \n"
    "   fnSystem032(&Img, &Key); \n"
    "   return TRUE; \n"
        "}\n\n");
    PrintHex("Data", payload, spayload);
    printf("#define HINT_BYTE 0x%0.2X\n\n", key_HintByte);
    PrintHex("pKey", key, skey);
    printf("\033[38;2;0;100;255m");
    printf("// [!] usage exampel \n");
    printf("\033[38;5;250m");
    printf("// RC4_Guard(Data, sizeof(Data), pKey, sizeof(pKey), HINT_BYTE);\n\n");
}
VOID generate_AES_output(IN PBYTE payload, IN SIZE_T spayload, IN PBYTE keys, IN BYTE key_HintByte, IN PBYTE iv, IN PBYTE Prog_name) {
    printf("\n\n#include \"heder.h\"\n\n");
    printf("BOOL PaddPayload(IN OUT PBYTE* pRawPayloadBuffer, IN OUT SIZE_T* sRawPayloadSize) {\n");
    printf("    if (*sRawPayloadSize %% 0x10 != 0) {\n");
    printf("        SIZE_T PaddedPayloadSize = *sRawPayloadSize + 0x10 - (*sRawPayloadSize %% 0x10);\n");
    printf("        PBYTE PaddedPayload = (PBYTE)ALLOC(PaddedPayloadSize);\n");
    printf("\n");
    printf("        RtlCopyMemory(PaddedPayload, *pRawPayloadBuffer, *sRawPayloadSize);\n");
    printf("        FREE(*pRawPayloadBuffer);\n");
    printf("        *pRawPayloadBuffer = PaddedPayload;\n");
    printf("        *sRawPayloadSize = PaddedPayloadSize;\n");
    printf("    }\n");
    printf("}\n");
    printf("\n");
    printf("BOOL AES_Guard(IN PBYTE pRawPayloadBuffer, IN SIZE_T sRawPayloadSize, IN PBYTE pProtectedKey, IN SIZE_T Skeys , IN BYTE key_HintByte, IN PBYTE pIv, OUT PBYTE* ppDencPayloadBuffer, OUT SIZE_T* psDencPayloadSize) {\n");
    printf("\n");
    printf("    BYTE            b = 0;\n");
    printf("    INT             i = 0;\n");
    printf("    PBYTE           pRealKey = (PBYTE)malloc(Skeys);\n");
    printf("\n");
    printf("    if (!pRealKey)\n");
    printf("        return FALSE;\n");
    printf("\n");
    printf("    while (1) {\n");
    printf("\n");
    printf("        if (((pProtectedKey[0] ^ b) - i) == key_HintByte)\n");
    printf("            break;\n");
    printf("        else\n");
    printf("            b++;\n");
    printf("    }\n");
    printf("\n");
    printf("    for (int i = 0; i < Skeys; i++) {\n");
    printf("        pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);\n");
    printf("    }\n");
    printf("\n");
    printf("    AES256_CBC_ctx AesCtx = { 0 };\n");
    printf("    RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));\n");
    printf("    AES256_CBC_init(&AesCtx, pRealKey, pIv);\n");
    printf("\n");
    printf("    if (PaddPayload(&pRawPayloadBuffer, &sRawPayloadSize)) {\n");
    printf("        *psDencPayloadSize = sRawPayloadSize;\n");
    printf("        AES256_CBC_decrypt(&AesCtx, pRawPayloadBuffer, sRawPayloadSize, ppDencPayloadBuffer);\n");
    printf("    }\n");
    printf("\n");
    printf("    return TRUE;\n");
    printf("}\n\n");
    PrintHex("data", payload, spayload);
    printf("#define HINT_BYTE 0x%0.2X\n\n", key_HintByte);
    PrintHex("pKey", keys, KEY_SIZE);
    PrintHex("IV", iv, IV_SIZE);
    printf("\033[38;2;0;100;255m");
    printf("// [!] usage exampel \n");
    printf("\033[38;5;250m");
    printf("// PBYTE dec_payload = NULL; \n");
    printf("// SIZE_T S_dec_payload = 0;\n");
    printf("// AES_Guard(data, sizeof(data), pKey, sizeof(pKey), HINT_BYTE, IV , &dec_payload, &S_dec_payload);\n");
    printf("\033[38;2;0;100;255m");
    printf("// [!] wille locate heder.h in same %s directory \n\n", Prog_name);
    printf("\033[38;5;250m");


}
VOID generate_XOR_output(IN PBYTE payload, IN SIZE_T spayload, IN PBYTE key, IN SIZE_T skey, IN BYTE key_HintByte) {

    printf("\n\n#include <stdio.h>\n"
        "#include <windows.h>\n\n"
        "VOID XOR_Guard(IN const PBYTE payload, IN SIZE_T payloadSize, IN const PBYTE pkey, IN SIZE_T keySize, IN BYTE hint) {\n"
        "    BYTE            b = 0; \n"
        "    INT             i = 0; \n"
        "    PBYTE           oKey = (PBYTE)malloc(keySize); \n"
        "    if (!oKey)\n"
        "        return FALSE; \n"
        "    while (1) {\n"
        "        if (((pkey[0] ^ b)) == hint)\n"
        "            break; \n"
        "        else\n"
        "            b++; \n"
        "    }\n"
        "    for (int i = 0; i < keySize; i++) {\n"
        "        oKey[i] = (BYTE)((pkey[i] ^ b) - i); \n"
        "    }\n"
        "    for (SIZE_T i = 0; i < payloadSize; ++i) {\n"
        "        payload[i] = (payload[i] << 1) | (payload[i] >> 7); \n"
        "        payload[i] = payload[i] ^ oKey[i %% keySize];\n"
        "   }\n"
        "}\n\n");
    PrintHex("Data", payload, spayload);
    printf("#define HINT_BYTE 0x%0.2X\n\n", key_HintByte);
    PrintHex("pkey", key, skey);
    printf("\033[38;2;0;100;255m");
    printf("// [!] usage exampel \n");
    printf("\033[38;5;250m");
    printf("// XOR_Guard(Data, sizeof(Data), pkey, sizeof(pkey), HINT_BYTE);\n\n");

}



//========================================================================================================================================//
// Help
//========================================================================================================================================//
void print_usage() {
    system("cls");
    system("chcp 65001 > nul");
    system("title Crypt_Guard - by Y.JANBOUBI");
    printf("\n");
    printf("\033[38;2;70;130;180m");  // Steel blue
    printf("╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("╚════════════════════════════════════════ Crypt_Guard - Security Tool ════════════════════════════════════════╝\n");
    printf("╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    printf("		\033[38;2;0;100;255m ██████╗██████╗ ██╗   ██╗██████╗ ████████╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗\n");
    printf("		\033[38;2;0;120;255m██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝     ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗\n");
    printf("		\033[38;2;0;150;255m██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║        ██║  ███╗██║   ██║███████║██████╔╝██║  ██║\n");
    printf("		\033[38;2;0;180;255m██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║        ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║\n");
    printf("		\033[38;2;70;200;255m╚██████╗██║  ██║   ██║   ██║        ██║███████╗╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝\n");
    printf("		\033[38;2;100;220;255m ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ \n\n");
    printf("\033[38;2;70;130;180m");
    printf("╔═════════════════════════════════════════════════════════════════════════════════════════════════════════════╗\n");
    printf("╚════════════════════════════════════════ Developed BY Y.JANBOUBI V1.0 ═══════════════════════════════════════╝\n");
    printf("╚═════════════════════════════════════════════════════════════════════════════════════════════════════════════╝\n\n");
    printf("\033[38;5;250m");
}
void print_help(char* arg0) {
    print_usage();
    printf("\033[38;2;70;130;180m");
    printf("[!] Encryption Types : (<XOR> <RC4> <AES>)\n");
    printf("[!] Usage Examples   : (%s <Encryption_Types> <file.bin>)\n", arg0);
    printf("\033[38;5;250m");
    getchar();
}


//========================================================================================================================================//
// AES structer
//========================================================================================================================================//
BOOL PaddPayload(IN OUT PBYTE* pRawPayloadBuffer, IN OUT SIZE_T* sRawPayloadSize) {
    if (*sRawPayloadSize % 0x10 != 0) {
        SIZE_T PaddedPayloadSize = *sRawPayloadSize + 0x10 - (*sRawPayloadSize % 0x10);
        PBYTE PaddedPayload = (PBYTE)ALLOC(PaddedPayloadSize);
        if (!PaddedPayload) {
            printf("[!] LocalAlloc failed with error: %d\n", GetLastError());
            return FALSE;
        }
        RtlCopyMemory(PaddedPayload, *pRawPayloadBuffer, *sRawPayloadSize);
        FREE(*pRawPayloadBuffer);
        *pRawPayloadBuffer = PaddedPayload;
        *sRawPayloadSize = PaddedPayloadSize;
    }

    return TRUE;
}
BOOL AesEncryptPayload(IN PBYTE pRawPayloadBuffer, IN SIZE_T sRawPayloadSize, OUT PBYTE* ppEncPayloadBuffer, OUT SIZE_T* psEncPayloadSize, OUT PBYTE pKey, OUT PBYTE pIv) {
    if (!pRawPayloadBuffer || !sRawPayloadSize || !ppEncPayloadBuffer || !psEncPayloadSize || !pKey || !pIv) {
        return FALSE;
    }

    AES256_CBC_ctx AesCtx = { 0 };
    RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));

    srand(GetTickCount64());
    for (DWORD i = 0; i < KEY_SIZE; i++)
        pKey[i] = (BYTE)(rand() % 0xFF);


    srand(GetTickCount64() * rand());
    for (DWORD i = 0; i < IV_SIZE; i++)
        pIv[i] = (BYTE)(rand() % 0xFF);


    if (PaddPayload(&pRawPayloadBuffer, &sRawPayloadSize)) {
        *psEncPayloadSize = sRawPayloadSize;
        AES256_CBC_init(&AesCtx, pKey, pIv);
        if (!AES256_CBC_encrypt(&AesCtx, pRawPayloadBuffer, sRawPayloadSize, ppEncPayloadBuffer)) {
            return FALSE;
        }
        return TRUE;
    }
    return FALSE;
}
BOOL AesDencryptPayload(IN PBYTE pRawPayloadBuffer, IN SIZE_T sRawPayloadSize, IN PBYTE pProtectedKey, IN SIZE_T Skeys, IN BYTE key_HintByte, IN PBYTE pIv, OUT PBYTE* ppDencPayloadBuffer, OUT SIZE_T* psDencPayloadSize) {

    BYTE            b = 0;
    INT             i = 0;
    PBYTE           pRealKey = (PBYTE)malloc(Skeys);

    if (!pRealKey)
        return -1;

    while (1) {

        if (((pProtectedKey[0] ^ b) - i) == key_HintByte)
            break;
        else
            b++;
    }

    for (int i = 0; i < Skeys; i++) {
        pRealKey[i] = (BYTE)((pProtectedKey[i] ^ b) - i);
    }


    AES256_CBC_ctx AesCtx = { 0 };
    RtlSecureZeroMemory(&AesCtx, sizeof(AES256_CBC_ctx));
    AES256_CBC_init(&AesCtx, pRealKey, pIv);

    if (PaddPayload(&pRawPayloadBuffer, &sRawPayloadSize)) {
        *psDencPayloadSize = sRawPayloadSize;
        AES256_CBC_decrypt(&AesCtx, pRawPayloadBuffer, sRawPayloadSize, ppDencPayloadBuffer);
    }

}
BOOL Write_heder_File(IN PBYTE pFileBuffer, IN DWORD dwFileSize) {

    HANDLE	hFile = INVALID_HANDLE_VALUE;
    DWORD	dwNumberOfBytesWritten = 0x00;

    if (!pFileBuffer || !dwFileSize)
        return FALSE;

    if ((hFile = CreateFileA(HEDER_NAME, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE) {
        printf("\t[!] CreateFileA Failed With Error: %d \n", GetLastError());
        goto _FUNC_CLEANUP;
    }

    if (!WriteFile(hFile, pFileBuffer, dwFileSize, &dwNumberOfBytesWritten, NULL) || dwFileSize != dwNumberOfBytesWritten) {
        printf("\t[!] WriteFile Failed With Error: %d \n", GetLastError());
        printf("\t[i] WriteFile Wrote %d Of %d Bytes \n", dwNumberOfBytesWritten, dwFileSize);
        goto _FUNC_CLEANUP;
    }

_FUNC_CLEANUP:
    if (hFile != INVALID_HANDLE_VALUE)
        CloseHandle(hFile);
    return dwNumberOfBytesWritten == dwFileSize ? TRUE : FALSE;
}
VOID heder() {
    const char* content =
        "#pragma once\n\n"
        "#include <Windows.h>\n"
        "#include <stdint.h> \n"
        "#include <stdio.h>\n\n"
        "typedef struct {\n"
        "    uint16_t slice[8];\n"
        "} AES_state;\n"
        "typedef struct {\n"
        "    AES_state rk[15];\n"
        "} AES256_ctx;\n"
        "typedef struct {\n"
        "    AES256_ctx ctx;\n"
        "    uint8_t iv[16];    \n"
        "} AES256_CBC_ctx;\n\n"
        "void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv);\n"
        "boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain);\n\n"
        "#define ALLOC(SIZE) LocalAlloc(LPTR, (SIZE_T)SIZE)\n"
        "#define FREE(BUFF) LocalFree((LPVOID)BUFF)\n\n"
        "static void LoadByte(AES_state* s, unsigned char byte, int r, int c) {\n"
        "    int i;\n"
        "    for (i = 0; i < 8; i++) {\n"
        "        s->slice[i] |= (uint16_t)(byte & 1) << (r * 4 + c);\n"
        "        byte >>= 1;\n"
        "    }\n"
        "}\n"
        "static void LoadBytes(AES_state* s, const unsigned char* data16) {\n"
        "    int c;\n"
        "    for (c = 0; c < 4; c++) {\n"
        "        int r;\n"
        "        for (r = 0; r < 4; r++) {\n"
        "            LoadByte(s, *(data16++), r, c);\n"
        "        }\n"
        "    }\n"
        "}\n"
        "static void SaveBytes(unsigned char* data16, const AES_state* s) {\n"
        "    int c;\n"
        "    for (c = 0; c < 4; c++) {\n"
        "        int r;\n"
        "        for (r = 0; r < 4; r++) {\n"
        "            int b;\n"
        "            uint8_t v = 0;\n"
        "            for (b = 0; b < 8; b++) {\n"
        "                v |= ((s->slice[b] >> (r * 4 + c)) & 1) << b;\n"
        "            }\n"
        "            *(data16++) = v;\n"
        "        }\n"
        "    }\n"
        "}\n"
        "static void SubBytes(AES_state* s, int inv) {\n"
        "   \n"
        "    uint16_t U0 = s->slice[7], U1 = s->slice[6], U2 = s->slice[5], U3 = s->slice[4];\n"
        "    uint16_t U4 = s->slice[3], U5 = s->slice[2], U6 = s->slice[1], U7 = s->slice[0];\n"
        "    uint16_t T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15, T16;\n"
        "    uint16_t T17, T18, T19, T20, T21, T22, T23, T24, T25, T26, T27, D;\n"
        "    uint16_t M1, M6, M11, M13, M15, M20, M21, M22, M23, M25, M37, M38, M39, M40;\n"
        "    uint16_t M41, M42, M43, M44, M45, M46, M47, M48, M49, M50, M51, M52, M53, M54;\n"
        "    uint16_t M55, M56, M57, M58, M59, M60, M61, M62, M63;\n"
        "    if (inv) {\n"
        "        uint16_t R5, R13, R17, R18, R19;\n"
        "        T23 = U0 ^ U3;\n"
        "        T22 = ~(U1 ^ U3);\n"
        "        T2 = ~(U0 ^ U1);\n"
        "        T1 = U3 ^ U4;\n"
        "        T24 = ~(U4 ^ U7);\n"
        "        R5 = U6 ^ U7;\n"
        "        T8 = ~(U1 ^ T23);\n"
        "        T19 = T22 ^ R5;\n"
        "        T9 = ~(U7 ^ T1);\n"
        "        T10 = T2 ^ T24;\n"
        "        T13 = T2 ^ R5;\n"
        "        T3 = T1 ^ R5;\n"
        "        T25 = ~(U2 ^ T1);\n"
        "        R13 = U1 ^ U6;\n"
        "        T17 = ~(U2 ^ T19);\n"
        "        T20 = T24 ^ R13;\n"
        "        T4 = U4 ^ T8;\n"
        "        R17 = ~(U2 ^ U5);\n"
        "        R18 = ~(U5 ^ U6);\n"
        "        R19 = ~(U2 ^ U4);\n"
        "        D = U0 ^ R17;\n"
        "        T6 = T22 ^ R17;\n"
        "        T16 = R13 ^ R19;\n"
        "        T27 = T1 ^ R18;\n"
        "        T15 = T10 ^ T27;\n"
        "        T14 = T10 ^ R18;\n"
        "        T26 = T3 ^ T16;\n"
        "    }\n"
        "    else {\n"
        "        T1 = U0 ^ U3;\n"
        "        T2 = U0 ^ U5;\n"
        "        T3 = U0 ^ U6;\n"
        "        T4 = U3 ^ U5;\n"
        "        T5 = U4 ^ U6;\n"
        "        T6 = T1 ^ T5;\n"
        "        T7 = U1 ^ U2;\n"
        "        T8 = U7 ^ T6;\n"
        "        T9 = U7 ^ T7;\n"
        "        T10 = T6 ^ T7;\n"
        "        T11 = U1 ^ U5;\n"
        "        T12 = U2 ^ U5;\n"
        "        T13 = T3 ^ T4;\n"
        "        T14 = T6 ^ T11;\n"
        "        T15 = T5 ^ T11;\n"
        "        T16 = T5 ^ T12;\n"
        "        T17 = T9 ^ T16;\n"
        "        T18 = U3 ^ U7;\n"
        "        T19 = T7 ^ T18;\n"
        "        T20 = T1 ^ T19;\n"
        "        T21 = U6 ^ U7;\n"
        "        T22 = T7 ^ T21;\n"
        "        T23 = T2 ^ T22;\n"
        "        T24 = T2 ^ T10;\n"
        "        T25 = T20 ^ T17;\n"
        "        T26 = T3 ^ T16;\n"
        "        T27 = T1 ^ T12;\n"
        "        D = U7;\n"
        "    }\n"
        "    M1 = T13 & T6;\n"
        "    M6 = T3 & T16;\n"
        "    M11 = T1 & T15;\n"
        "    M13 = (T4 & T27) ^ M11;\n"
        "    M15 = (T2 & T10) ^ M11;\n"
        "    M20 = T14 ^ M1 ^ (T23 & T8) ^ M13;\n"
        "    M21 = (T19 & D) ^ M1 ^ T24 ^ M15;\n"
        "    M22 = T26 ^ M6 ^ (T22 & T9) ^ M13;\n"
        "    M23 = (T20 & T17) ^ M6 ^ M15 ^ T25;\n"
        "    M25 = M22 & M20;\n"
        "    M37 = M21 ^ ((M20 ^ M21) & (M23 ^ M25));\n"
        "    M38 = M20 ^ M25 ^ (M21 | (M20 & M23));\n"
        "    M39 = M23 ^ ((M22 ^ M23) & (M21 ^ M25));\n"
        "    M40 = M22 ^ M25 ^ (M23 | (M21 & M22));\n"
        "    M41 = M38 ^ M40;\n"
        "    M42 = M37 ^ M39;\n"
        "    M43 = M37 ^ M38;\n"
        "    M44 = M39 ^ M40;\n"
        "    M45 = M42 ^ M41;\n"
        "    M46 = M44 & T6;\n"
        "    M47 = M40 & T8;\n"
        "    M48 = M39 & D;\n"
        "    M49 = M43 & T16;\n"
        "    M50 = M38 & T9;\n"
        "    M51 = M37 & T17;\n"
        "    M52 = M42 & T15;\n"
        "    M53 = M45 & T27;\n"
        "    M54 = M41 & T10;\n"
        "    M55 = M44 & T13;\n"
        "    M56 = M40 & T23;\n"
        "    M57 = M39 & T19;\n"
        "    M58 = M43 & T3;\n"
        "    M59 = M38 & T22;\n"
        "    M60 = M37 & T20;\n"
        "    M61 = M42 & T1;\n"
        "    M62 = M45 & T4;\n"
        "    M63 = M41 & T2;\n"
        "    if (inv) {\n"
        "        uint16_t P0 = M52 ^ M61;\n"
        "        uint16_t P1 = M58 ^ M59;\n"
        "        uint16_t P2 = M54 ^ M62;\n"
        "        uint16_t P3 = M47 ^ M50;\n"
        "        uint16_t P4 = M48 ^ M56;\n"
        "        uint16_t P5 = M46 ^ M51;\n"
        "        uint16_t P6 = M49 ^ M60;\n"
        "        uint16_t P7 = P0 ^ P1;\n"
        "        uint16_t P8 = M50 ^ M53;\n"
        "        uint16_t P9 = M55 ^ M63;\n"
        "        uint16_t P10 = M57 ^ P4;\n"
        "        uint16_t P11 = P0 ^ P3;\n"
        "        uint16_t P12 = M46 ^ M48;\n"
        "        uint16_t P13 = M49 ^ M51;\n"
        "        uint16_t P14 = M49 ^ M62;\n"
        "        uint16_t P15 = M54 ^ M59;\n"
        "        uint16_t P16 = M57 ^ M61;\n"
        "        uint16_t P17 = M58 ^ P2;\n"
        "        uint16_t P18 = M63 ^ P5;\n"
        "        uint16_t P19 = P2 ^ P3;\n"
        "        uint16_t P20 = P4 ^ P6;\n"
        "        uint16_t P22 = P2 ^ P7;\n"
        "        uint16_t P23 = P7 ^ P8;\n"
        "        uint16_t P24 = P5 ^ P7;\n"
        "        uint16_t P25 = P6 ^ P10;\n"
        "        uint16_t P26 = P9 ^ P11;\n"
        "        uint16_t P27 = P10 ^ P18;\n"
        "        uint16_t P28 = P11 ^ P25;\n"
        "        uint16_t P29 = P15 ^ P20;\n"
        "        s->slice[7] = P13 ^ P22;\n"
        "        s->slice[6] = P26 ^ P29;\n"
        "        s->slice[5] = P17 ^ P28;\n"
        "        s->slice[4] = P12 ^ P22;\n"
        "        s->slice[3] = P23 ^ P27;\n"
        "        s->slice[2] = P19 ^ P24;\n"
        "        s->slice[1] = P14 ^ P23;\n"
        "        s->slice[0] = P9 ^ P16;\n"
        "    }\n"
        "    else {\n"
        "        uint16_t L0 = M61 ^ M62;\n"
        "        uint16_t L1 = M50 ^ M56;\n"
        "        uint16_t L2 = M46 ^ M48;\n"
        "        uint16_t L3 = M47 ^ M55;\n"
        "        uint16_t L4 = M54 ^ M58;\n"
        "        uint16_t L5 = M49 ^ M61;\n"
        "        uint16_t L6 = M62 ^ L5;\n"
        "        uint16_t L7 = M46 ^ L3;\n"
        "        uint16_t L8 = M51 ^ M59;\n"
        "        uint16_t L9 = M52 ^ M53;\n"
        "        uint16_t L10 = M53 ^ L4;\n"
        "        uint16_t L11 = M60 ^ L2;\n"
        "        uint16_t L12 = M48 ^ M51;\n"
        "        uint16_t L13 = M50 ^ L0;\n"
        "        uint16_t L14 = M52 ^ M61;\n"
        "        uint16_t L15 = M55 ^ L1;\n"
        "        uint16_t L16 = M56 ^ L0;\n"
        "        uint16_t L17 = M57 ^ L1;\n"
        "        uint16_t L18 = M58 ^ L8;\n"
        "        uint16_t L19 = M63 ^ L4;\n"
        "        uint16_t L20 = L0 ^ L1;\n"
        "        uint16_t L21 = L1 ^ L7;\n"
        "        uint16_t L22 = L3 ^ L12;\n"
        "        uint16_t L23 = L18 ^ L2;\n"
        "        uint16_t L24 = L15 ^ L9;\n"
        "        uint16_t L25 = L6 ^ L10;\n"
        "        uint16_t L26 = L7 ^ L9;\n"
        "        uint16_t L27 = L8 ^ L10;\n"
        "        uint16_t L28 = L11 ^ L14;\n"
        "        uint16_t L29 = L11 ^ L17;\n"
        "        s->slice[7] = L6 ^ L24;\n"
        "        s->slice[6] = ~(L16 ^ L26);\n"
        "        s->slice[5] = ~(L19 ^ L28);\n"
        "        s->slice[4] = L6 ^ L21;\n"
        "        s->slice[3] = L20 ^ L22;\n"
        "        s->slice[2] = L25 ^ L29;\n"
        "        s->slice[1] = ~(L13 ^ L27);\n"
        "        s->slice[0] = ~(L6 ^ L23);\n"
        "    }\n"
        "}\n\n"
        "#define BIT_RANGE(from,to) ((uint16_t)((1 << ((to) - (from))) - 1) << (from))\n"
        "#define BIT_RANGE_LEFT(x,from,to,shift) (((x) & BIT_RANGE((from), (to))) << (shift))\n"
        "#define BIT_RANGE_RIGHT(x,from,to,shift) (((x) & BIT_RANGE((from), (to))) >> (shift))\n"
        "#define ROT(x,b) (((x) >> ((b) * 4)) | ((x) << ((4-(b)) * 4)))\n\n"
        "static void ShiftRows(AES_state* s) {\n"
        "    int i;\n"
        "    for (i = 0; i < 8; i++) {\n"
        "        uint16_t v = s->slice[i];\n"
        "        s->slice[i] =\n"
        "            (v & BIT_RANGE(0, 4)) |\n"
        "            BIT_RANGE_LEFT(v, 4, 5, 3) | BIT_RANGE_RIGHT(v, 5, 8, 1) |\n"
        "            BIT_RANGE_LEFT(v, 8, 10, 2) | BIT_RANGE_RIGHT(v, 10, 12, 2) |\n"
        "            BIT_RANGE_LEFT(v, 12, 15, 1) | BIT_RANGE_RIGHT(v, 15, 16, 3);\n"
        "    }\n"
        "}\n"
        "static void InvShiftRows(AES_state* s) {\n"
        "    int i;\n"
        "    for (i = 0; i < 8; i++) {\n"
        "        uint16_t v = s->slice[i];\n"
        "        s->slice[i] =\n"
        "            (v & BIT_RANGE(0, 4)) |\n"
        "            BIT_RANGE_LEFT(v, 4, 7, 1) | BIT_RANGE_RIGHT(v, 7, 8, 3) |\n"
        "            BIT_RANGE_LEFT(v, 8, 10, 2) | BIT_RANGE_RIGHT(v, 10, 12, 2) |\n"
        "            BIT_RANGE_LEFT(v, 12, 13, 3) | BIT_RANGE_RIGHT(v, 13, 16, 1);\n"
        "    }\n"
        "}\n"
        "static void MixColumns(AES_state* s, int inv) {\n"
        "    uint16_t s0 = s->slice[0], s1 = s->slice[1], s2 = s->slice[2], s3 = s->slice[3];\n"
        "    uint16_t s4 = s->slice[4], s5 = s->slice[5], s6 = s->slice[6], s7 = s->slice[7];\n"
        "    uint16_t s0_01 = s0 ^ ROT(s0, 1), s0_123 = ROT(s0_01, 1) ^ ROT(s0, 3);\n"
        "    uint16_t s1_01 = s1 ^ ROT(s1, 1), s1_123 = ROT(s1_01, 1) ^ ROT(s1, 3);\n"
        "    uint16_t s2_01 = s2 ^ ROT(s2, 1), s2_123 = ROT(s2_01, 1) ^ ROT(s2, 3);\n"
        "    uint16_t s3_01 = s3 ^ ROT(s3, 1), s3_123 = ROT(s3_01, 1) ^ ROT(s3, 3);\n"
        "    uint16_t s4_01 = s4 ^ ROT(s4, 1), s4_123 = ROT(s4_01, 1) ^ ROT(s4, 3);\n"
        "    uint16_t s5_01 = s5 ^ ROT(s5, 1), s5_123 = ROT(s5_01, 1) ^ ROT(s5, 3);\n"
        "    uint16_t s6_01 = s6 ^ ROT(s6, 1), s6_123 = ROT(s6_01, 1) ^ ROT(s6, 3);\n"
        "    uint16_t s7_01 = s7 ^ ROT(s7, 1), s7_123 = ROT(s7_01, 1) ^ ROT(s7, 3);\n"
        "    s->slice[0] = s7_01 ^ s0_123;\n"
        "    s->slice[1] = s7_01 ^ s0_01 ^ s1_123;\n"
        "    s->slice[2] = s1_01 ^ s2_123;\n"
        "    s->slice[3] = s7_01 ^ s2_01 ^ s3_123;\n"
        "    s->slice[4] = s7_01 ^ s3_01 ^ s4_123;\n"
        "    s->slice[5] = s4_01 ^ s5_123;\n"
        "    s->slice[6] = s5_01 ^ s6_123;\n"
        "    s->slice[7] = s6_01 ^ s7_123;\n"
        "    if (inv) {\n"
        "        uint16_t t0_02 = s->slice[0] ^ ROT(s->slice[0], 2);\n"
        "        uint16_t t1_02 = s->slice[1] ^ ROT(s->slice[1], 2);\n"
        "        uint16_t t2_02 = s->slice[2] ^ ROT(s->slice[2], 2);\n"
        "        uint16_t t3_02 = s->slice[3] ^ ROT(s->slice[3], 2);\n"
        "        uint16_t t4_02 = s->slice[4] ^ ROT(s->slice[4], 2);\n"
        "        uint16_t t5_02 = s->slice[5] ^ ROT(s->slice[5], 2);\n"
        "        uint16_t t6_02 = s->slice[6] ^ ROT(s->slice[6], 2);\n"
        "        uint16_t t7_02 = s->slice[7] ^ ROT(s->slice[7], 2);\n"
        "        s->slice[0] ^= t6_02;\n"
        "        s->slice[1] ^= t6_02 ^ t7_02;\n"
        "        s->slice[2] ^= t0_02 ^ t7_02;\n"
        "        s->slice[3] ^= t1_02 ^ t6_02;\n"
        "        s->slice[4] ^= t2_02 ^ t6_02 ^ t7_02;\n"
        "        s->slice[5] ^= t3_02 ^ t7_02;\n"
        "        s->slice[6] ^= t4_02;\n"
        "        s->slice[7] ^= t5_02;\n"
        "    }\n"
        "}\n"
        "static void AddRoundKey(AES_state* s, const AES_state* round) {\n"
        "    int b;\n"
        "    for (b = 0; b < 8; b++) {\n"
        "        s->slice[b] ^= round->slice[b];\n"
        "    }\n"
        "}\n"
        "static void GetOneColumn(AES_state* s, const AES_state* a, int c) {\n"
        "    int b;\n"
        "    for (b = 0; b < 8; b++) {\n"
        "        s->slice[b] = (a->slice[b] >> c) & 0x1111;\n"
        "    }\n"
        "}\n"
        "static void KeySetupColumnMix(AES_state* s, AES_state* r, const AES_state* a, int c1, int c2) {\n"
        "    int b;\n"
        "    for (b = 0; b < 8; b++) {\n"
        "        r->slice[b] |= ((s->slice[b] ^= ((a->slice[b] >> c2) & 0x1111)) & 0x1111) << c1;\n"
        "    }\n"
        "}\n"
        "static void KeySetupTransform(AES_state* s, const AES_state* r) {\n"
        "    int b;\n"
        "    for (b = 0; b < 8; b++) {\n"
        "        s->slice[b] = ((s->slice[b] >> 4) | (s->slice[b] << 12)) ^ r->slice[b];\n"
        "    }\n"
        "}\n"
        "static void MultX(AES_state* s) {\n"
        "    uint16_t top = s->slice[7];\n"
        "    s->slice[7] = s->slice[6];\n"
        "    s->slice[6] = s->slice[5];\n"
        "    s->slice[5] = s->slice[4];\n"
        "    s->slice[4] = s->slice[3] ^ top;\n"
        "    s->slice[3] = s->slice[2] ^ top;\n"
        "    s->slice[2] = s->slice[1];\n"
        "    s->slice[1] = s->slice[0] ^ top;\n"
        "    s->slice[0] = top;\n"
        "}\n"
        "static void AES_setup(AES_state* rounds, const uint8_t* key, int nkeywords, int nrounds)\n"
        "{\n"
        "    int i;\n"
        "    AES_state rcon = { {1,0,0,0,0,0,0,0} };\n"
        "    int pos = 0;\n"
        "    AES_state column;\n"
        "    for (i = 0; i < nrounds + 1; i++) {\n"
        "        int b;\n"
        "        for (b = 0; b < 8; b++) {\n"
        "            rounds[i].slice[b] = 0;\n"
        "        }\n"
        "    }\n"
        "    for (i = 0; i < nkeywords; i++) {\n"
        "        int r;\n"
        "        for (r = 0; r < 4; r++) {\n"
        "            LoadByte(&rounds[i >> 2], *(key++), r, i & 3);\n"
        "        }\n"
        "    }\n"
        "    GetOneColumn(&column, &rounds[(nkeywords - 1) >> 2], (nkeywords - 1) & 3);\n"
        "    for (i = nkeywords; i < 4 * (nrounds + 1); i++) {\n"
        "        /* Transform column */\n"
        "        if (pos == 0) {\n"
        "            SubBytes(&column, 0);\n"
        "            KeySetupTransform(&column, &rcon);\n"
        "            MultX(&rcon);\n"
        "        }\n"
        "        else if (nkeywords > 6 && pos == 4) {\n"
        "            SubBytes(&column, 0);\n"
        "        }\n"
        "        if (++pos == nkeywords) pos = 0;\n"
        "        KeySetupColumnMix(&column, &rounds[i >> 2], &rounds[(i - nkeywords) >> 2], i & 3, (i - nkeywords) & 3);\n"
        "    }\n"
        "}\n"
        "static void AES_decrypt(const AES_state* rounds, int nrounds, unsigned char* plain16, const unsigned char* cipher16) {\n"
        "    AES_state s = { {0} };\n"
        "    int round;\n"
        "    rounds += nrounds;\n"
        "    LoadBytes(&s, cipher16);\n"
        "    AddRoundKey(&s, rounds--);\n"
        "    for (round = 1; round < nrounds; round++) {\n"
        "        InvShiftRows(&s);\n"
        "        SubBytes(&s, 1);\n"
        "        AddRoundKey(&s, rounds--);\n"
        "        MixColumns(&s, 1);\n"
        "    }\n"
        "    InvShiftRows(&s);\n"
        "    SubBytes(&s, 1);\n"
        "    AddRoundKey(&s, rounds);\n"
        "    SaveBytes(plain16, &s);\n"
        "}\n"
        "static void Xor128(uint8_t* buf1, const uint8_t* buf2) {\n"
        "    size_t i;\n"
        "    for (i = 0; i < 16; i++) {\n"
        "        buf1[i] ^= buf2[i];\n"
        "    }\n"
        "}\n"
        "static void AESCBC_decrypt(const AES_state* rounds, uint8_t* iv, int nk, size_t blocks, unsigned char* plain, const unsigned char* encrypted) {\n"
        "    size_t i;\n"
        "    uint8_t next_iv[16];\n"
        "    for (i = 0; i < blocks; i++) {\n"
        "        memcpy(next_iv, encrypted, 16);\n"
        "        AES_decrypt(rounds, nk, plain, encrypted);\n"
        "        Xor128(plain, iv);\n"
        "        memcpy(iv, next_iv, 16);\n"
        "        plain += 16;\n"
        "        encrypted += 16;\n"
        "    }\n"
        "}\n"
        "void AES256_init(AES256_ctx* ctx, const unsigned char* key32) {\n"
        "    AES_setup(ctx->rk, key32, 8, 14);\n"
        "}\n"
        "void AES256_CBC_init(OUT AES256_CBC_ctx* ctx, IN const unsigned char* key16, IN const uint8_t* iv)\n"
        "{\n"
        "    AES256_init(&(ctx->ctx), key16);\n"
        "    memcpy(ctx->iv, iv, 16);\n"
        "}\n"
        "boolean AES256_CBC_decrypt(IN AES256_CBC_ctx* ctx, IN const unsigned char* encrypted, IN size_t ciphersize, OUT PBYTE* plain)\n"
        "{\n"
        "    if (ciphersize % 16 != 0)\n"
        "        return FALSE;\n"
        "    size_t blocks = ciphersize / 16;\n"
        "    *plain = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ciphersize);\n"
        "    if (*plain != NULL)\n"
        "        AESCBC_decrypt(ctx->ctx.rk, ctx->iv, 14, blocks, *plain, encrypted);\n"
        "    else\n"
        "        return FALSE;\n"
        "    return TRUE;\n"
        "}\n";

    //extern const char* content; // Assume content is accessible
    if (!Write_heder_File((PBYTE)content, strlen(content))) {
        printf("[!] Failed to write header file\n");
    }

}
VOID AESGenerateProtectedKey(IN PBYTE pKey, IN SIZE_T sKey, OUT PBYTE* ppProtectedKey) {
    if (!pKey || !sKey)
        return;

    srand((unsigned int)time(NULL));
    BYTE b = (BYTE)(rand() % 0xFF);                 // Generate random key
    PBYTE  pProtectedKey = (PBYTE)malloc(sKey);     // allocated buffer for protected key


    // generate protected key 
    for (int i = 0; i < sKey; i++) {
        pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
    }

    *ppProtectedKey = pProtectedKey;
}



//========================================================================================================================================//
// RC4 structer 
//========================================================================================================================================//
typedef struct {
    DWORD Length;
    DWORD MaximumLength;
    PVOID Buffer;
} USTRING;
typedef NTSTATUS(NTAPI* fnSystemFunction032)(USTRING* Img, USTRING* Key);
BOOL Rc4Encrypt(IN PBYTE pRc4Key, IN DWORD dwRc4KeySize, IN OUT PBYTE pPayloadData, IN DWORD sPayloadSize) {
    NTSTATUS STATUS = 0;
    USTRING Key = { .Buffer = pRc4Key, .Length = dwRc4KeySize, .MaximumLength = dwRc4KeySize };
    USTRING Img = { .Buffer = pPayloadData, .Length = sPayloadSize, .MaximumLength = sPayloadSize };

    fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
    if (!SystemFunction032) {
        printf("[!] GetProcAddress for SystemFunction032 FAILED With Error: %d in Rc4Encrypt Function\n", GetLastError());
        return FALSE;
    }

    STATUS = SystemFunction032(&Img, &Key);
    if (STATUS != 0) {
        printf("[!] SystemFunction032 Encryption FAILED With Error: 0x%0.8X\n", STATUS);
        return FALSE;
    }
    return TRUE;
}
BOOL GenerateProtectedKey(IN SIZE_T sKey, OUT PBYTE* ppOriginalKey, OUT PBYTE* ppProtectedKey, OUT BYTE* H_intByte) {
    if (sKey == 0)
        return FALSE;

    // generated the random byte 
    srand((unsigned int)time(NULL));
    BYTE b = (BYTE)(rand() % 0xFF);            // generat random key 
    PBYTE pKey = (PBYTE)malloc(sKey);          // alloca buffer for originale key 
    PBYTE pProtectedKey = (PBYTE)malloc(sKey); // alloca buffer for protected key 


    if (!pKey || !pProtectedKey) {
        if (pKey) free(pKey);
        if (pProtectedKey) free(pProtectedKey);
        return FALSE;
    }

    // generate originale key 
    for (int i = 0; i < sKey; i++) {
        pKey[i] = (BYTE)rand() % 0xFF;
    }

    // generate protected key 
    for (int i = 0; i < sKey; i++) {
        pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
    }


    *ppProtectedKey = pProtectedKey;
    *ppOriginalKey = pKey;
    *H_intByte = pKey[0];


    return TRUE;
}



//========================================================================================================================================//
// XOR structer 
//========================================================================================================================================//
VOID xor_encrypt(IN const PBYTE payload, IN SIZE_T payloadSize, IN const PBYTE key, IN SIZE_T keySize) {
    for (SIZE_T i = 0; i < payloadSize; ++i) {
        payload[i] = payload[i] ^ key[i % keySize]; // Single XOR with key
        payload[i] = (payload[i] >> 1) | (payload[i] << 7); // Rotate right
    }
}
VOID xor_decrypt(IN const PBYTE payload, IN SIZE_T payloadSize, IN const PBYTE pkey, IN SIZE_T keySize, IN BYTE hint) {

    BYTE            b = 0;
    INT             i = 0;
    PBYTE           oKey = (PBYTE)malloc(keySize);
    if (!oKey)
        return FALSE;
    while (1) {
        if (((pkey[0] ^ b)) == hint)
            break;
        else
            b++;
    }
    for (int i = 0; i < keySize; i++) {
        oKey[i] = (BYTE)((pkey[i] ^ b) - i);
    }

    for (SIZE_T i = 0; i < payloadSize; ++i) {
        payload[i] = (payload[i] << 1) | (payload[i] >> 7); // Rotate right
        payload[i] = payload[i] ^ oKey[i % keySize]; // Single XOR with key
    }
}


