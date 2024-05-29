#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
using namespace std;


constexpr unsigned int P32 = 0xB7E15163;
constexpr unsigned int Q32 = 0x9E3779B9;
constexpr int ROUNDS = 12;
constexpr int WORD_SIZE = 32;
constexpr int BYTE_SIZE = 8;


inline unsigned int ROL(unsigned int x, unsigned int n) {
    return (x << n) | (x >> (WORD_SIZE - n));
}


inline unsigned int ROR(unsigned int x, unsigned int n) {
    return (x >> n) | (x << (WORD_SIZE - n));
}


void RC5_Key_Schedule(const unsigned int* K, unsigned int* S) {
    constexpr int b = 16; 
    constexpr int u = WORD_SIZE / BYTE_SIZE;
    constexpr int c = b / u;
    constexpr int t = 2 * (ROUNDS + 1);

    // Initialize S array
    S[0] = P32;
    for (int i = 1; i < t; ++i) {
        S[i] = S[i - 1] + Q32;
    }

    // Initialize L array
    unsigned int L[c] = {0};
    for (int i = b - 1; i >= 0; --i) {
        L[i / u] = (L[i / u] << BYTE_SIZE) + reinterpret_cast<const unsigned char*>(K)[i];
    }

    // Mixing
    unsigned int A = 0, B = 0;
    int v = 3 * max(t, c);
    for (int s = 0, i = 0, j = 0; s < v; ++s) {
        A = S[i] = ROL(S[i] + A + B, 3);
        B = L[j] = ROL(L[j] + A + B, (A + B) % WORD_SIZE);
        i = (i + 1) % t;
        j = (j + 1) % c;
    }
}


void RC5_Encrypt(const unsigned int* M, unsigned int* C, const unsigned int* S) {
    unsigned int A = M[0] + S[0];
    unsigned int B = M[1] + S[1];

    for (int i = 1; i <= ROUNDS; ++i) {
        A = ROL(A ^ B, B % WORD_SIZE) + S[2 * i];
        B = ROL(B ^ A, A % WORD_SIZE) + S[2 * i + 1];
    }

    C[0] = A;
    C[1] = B;
}


void RC5_Decrypt(const unsigned int* C, unsigned int* M, const unsigned int* S) {
    unsigned int A = C[0];
    unsigned int B = C[1];

    for (int i = ROUNDS; i > 0; --i) {
        B = ROR(B - S[2 * i + 1], A % WORD_SIZE) ^ A;
        A = ROR(A - S[2 * i], B % WORD_SIZE) ^ B;
    }

    M[0] = A - S[0];
    M[1] = B - S[1];
}


string Task1(const unsigned int* source, unsigned int sourceSize, 
const unsigned int* key, bool encryptionMode) {
    stringstream functionOutput;
    unsigned int S[2 * (ROUNDS + 1)];
    RC5_Key_Schedule(key, S);

    for (unsigned int i = 0; i < sourceSize; i += 2) {
        unsigned int M[2] = {source[i], source[i + 1]};
        unsigned int C[2] = {0, 0};

        if (encryptionMode) {
            RC5_Encrypt(M, C, S);
        } else {
            RC5_Decrypt(M, C, S);
        }

        functionOutput << uppercase << hex << setfill('0') << setw(8) << C[0] 
        << " " << setw(8) << C[1];
        if (i + 2 < sourceSize) {
            functionOutput << " ";
        }
    }

    return functionOutput.str();
}
