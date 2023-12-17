#include <iostream> 
#include <vector>
#include <bitset> 
#include <cstdint> 

const uint32_t h0 = 0x6a09e667;
const uint32_t h1 = 0xbb67ae85; 
const uint32_t h2 = 0x3c6ef372;
const uint32_t h3 = 0xa54ff53a; 
const uint32_t h4 = 0x510e527f; 
const uint32_t h5 = 0x9b05688c; 
const uint32_t h6 = 0x1f83d9ab; 
const uint32_t h7 = 0x5be0cd19; 

const std::vector<uint32_t> k = {
 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 }; 

// SHA-256 functions
#define ROTR(X, n) (((X) >>(n)) | ((X) << (32 - (n))))
#define SHR(X, n) ((X) >>(n))
#define CH(x, y, z) (((x) & (y)) ^ ( ~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))


void sha256(std::string input) {
    // Pre-processing
    std::vector<uint8_t> message;
    message.reserve(input.size() + 9);

    message.insert(message.end(), input.begin(), input.end());
    message.push_back(0X80);

    size_t original_size = input.size();
    size_t k = 64 - ((original_size + 1 + 8) % 64);
    message.insert(message.end(), k, 0);

    uint64_t bit_length = original_size * 8;
    for (int i = 7; i >= 0; --i)
    {
        message.push_back(static_cast<uint8_t>((bit_length >> (i * 8)) & 0xFF));
    }

    // Process the message in successive 512-bit chunks
     for (size_t i = 0; i < message.size(); i += 64) {
        std::vector<uint32_t> w(64);
        for (int t = 0; t < 16; ++t) {
            w[t] = (message[i + t*4] << 24) | (message[i + t*4 + 1] << 16) | (message[i + t*4 + 2] << 8) | message[i + t*4 + 3];
        }
        for (int t = 16; t < 64; ++t) {
            w[t] = SIG1(w[t-2]) + w[t-7] + SIG0(w[t-15]) + w[t-16];
        }

    // Produce the final hash value
    uint32_t a = h0;
    uint32_t b = h1;
    uint32_t c = h2;
    uint32_t d = h3;
    uint32_t e = h4;
    uint32_t f = h5;
    uint32_t g = h6;
    uint32_t h = h7;

    for (int t = 0; t < 64; ++t) {
        uint32_t T1 = h + EP1(e) + CH(e, f, g) + k[t] + w[t];
        uint32_t T2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;

    std::cout << std::hex << h0 << h1 << h2 << h3 << h4 << h5 << h6 << h7 << std::endl;
}

int main() {
    std::string input = "your input string";
    sha256(input);
    return 0;
}