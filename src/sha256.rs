// sha256 spec is here:
// https://csrc.nist.gov/publications/detail/fips/180/4/final
// (pdf: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

// block size is 512 bits (64 bytes, 16 32-bit words)
const BLOCK_SIZE = 512 / 8;

// digest size 256 bits (32 bytes)
const DIGEST_SIZE = 256 / 8;

// word size 32 bits (4 bytes)
const WORD_SIZE = 32 / 8;

// the output of the sha256 hash function
pub struct Hash {
    bytes: [u8; DIGEST_SIZE],
}

// TODO: what the symbols here mean

// "SHA-256 [uses] six logical functions, where each function operates on 32-bit words,
//  which are represented as x, y, and z. The result of each function is a new 32-bit word."
// Ch(x,y,z) = (x^y) ⊕ (-x^z)
// Maj(x,y,z) = (x^y) ⊕ (x^z) ⊕ (y^z)
// Σ (0 -> 256) (x) = ROTR^2 (x) + ROTR^13 (x) + ROTR^22 (x)
// Σ (1 -> 256) (x) = ROTR^6 (x) + ROTR^11 (x) + ROTR^25 (x)
// σ (0 -> 256) (x) = ROTR^7 (x) + ROTR^18 (x) + SHR^3 (x)
// σ (1 -> 256) (x) = ROTR^17 (x) + ROTR^19 (x) + SHR^10 (x)

// "SHA-256 [uses a] sequence of sixty-four constant 32-bit words, ...
//  These words represent the first thirty-two bits of the fractional parts of
//  the cube roots of the first sixty-four prime numbers."
const CUBE_ROOTS: [u32; 64] = [
    0x428a2f98,
    0x71374491,
    0xb5c0fbcf,
    0xe9b5dba5,
    0x3956c25b,
    0x59f111f1,
    0x923f82a4,
    0xab1c5ed5,
    0xd807aa98,
    0x12835b01,
    0x243185be,
    0x550c7dc3,
    0x72be5d74,
    0x80deb1fe,
    0x9bdc06a7,
    0xc19bf174,
    0xe49b69c1,
    0xefbe4786,
    0x0fc19dc6,
    0x240ca1cc,
    0x2de92c6f,
    0x4a7484aa,
    0x5cb0a9dc,
    0x76f988da,
    0x983e5152,
    0xa831c66d,
    0xb00327c8,
    0xbf597fc7,
    0xc6e00bf3,
    0xd5a79147,
    0x06ca6351,
    0x14292967,
    0x27b70a85,
    0x2e1b2138,
    0x4d2c6dfc,
    0x53380d13,
    0x650a7354,
    0x766a0abb,
    0x81c2c92e,
    0x92722c85,
    0xa2bfe8a1,
    0xa81a664b,
    0xc24b8b70,
    0xc76c51a3,
    0xd192e819,
    0xd6990624,
    0xf40e3585,
    0x106aa070,
    0x19a4c116,
    0x1e376c08,
    0x2748774c,
    0x34b0bcb5,
    0x391c0cb3,
    0x4ed8aa4a,
    0x5b9cca4f,
    0x682e6ff3,
    0x748f82ee,
    0x78a5636f,
    0x84c87814,
    0x8cc70208,
    0x90befffa,
    0xa4506ceb,
    0xbef9a3f7,
    0xc67178f2,
];

// Padding the Message
//
// "The purpose of this padding is to ensure that the padded message is a multiple of 512 or 1024
//  bits, depending on the algorithm. Padding can be inserted before hash computation begins on a
//  message, or at any other time during the hash computation prior to processing the block(s) that
//  will contain the padding."
//
// "Suppose that the length of the message, M, is l bits. Append the bit “1” to the end of the
//  message, followed by k zero bits, where k is the smallest, non-negative solution to the equation l+1+k = 448 mod 512.
//  Then append the 64-bit block that is equal to the number l expressed
//  using a binary representation. For example, the (8-bit ASCII) message “abc” has length 8 * 3 = 24,
//  so the message is padded with a one bit, then 448-(24+1)=423 zero bits, and then
//  the message length, to become the 512-bit padded message:
//
//                                 (423 bits)  (64 bits)
//  01100001 01100010 01100011  1  00...00     00...011000
//     "a"      "b"      "c"                       l = 24
//
//  The length of the padded message should now be a multiple of 512 bits."


// Parsing the Message
//
// "The message and its padding must be parsed into N m-bit blocks."
//
// "For SHA-1, SHA-224 and SHA-256, the message and its padding are parsed into N 512-bit
//  blocks, M(1), M(2),..., M(N). Since the 512 bits of the input block may be expressed as sixteen 32-bit
//  words, the first 32 bits of message block i are denoted
//  M0(i), the next 32 bits are M1(i), and so on up to M15(i).

// Setting the Initial Hash Value (H(0))
//
// "Before hash computation begins for each of the secure hash algorithms, the initial hash value,
// H(0), must be set. The size and number of words in H(0) depends on the message digest size."
//
// "For SHA-256, the initial hash value, H(0), shall consist of the following eight 32-bit words, in hex:
//  H0(0) = 6a09e667
//  H1(0) = bb67ae85
//  H2(0) = 3c6ef372
//  H3(0) = a54ff53a
//  H4(0) = 510e527f
//  H5(0) = 9b05688c
//  H6(0) = 1f83d9ab
//  H7(0) = 5be0cd19
//
//  These words were obtained by taking the first thirty-two bits of the fractional parts of the square
//  roots of the first eight prime numbers."


// SHA-256
//
// "SHA-256 may be used to hash a message, M, having a length of l bits, where 0 <= l < 2^64.
//  The algorithm uses
//    1) a message schedule of sixty-four 32-bit words,
//    2) eight working variables of 32 bits each, and
//    3) a hash value of eight 32-bit words.
//  The final result of SHA-256 is a 256-bit message digest."
//
// "The words of the message schedule are labeled W0, W1,..., W63.
//  The eight working variables are labeled a, b, c, d, e, f, g, and h.
//  The words of the hash value are labeled H0(i), H1(i),..., H7(i),
//  which will hold the initial hash value, H(0),
//  replaced by each successive intermediate hash value
//  (after each message block is processed), H(i), and ending with the final hash value, H(N).
//  SHA-256 also uses two temporary words, T1 and T2."

// SHA-256 Preprocessing
//
//  1. Set the initial hash value, H(0)
//  2. The message is padded and parsed


// SHA-256 Hash Computation
//
// "The SHA-256 hash computation uses functions and constants previously defined
//  Addition is performed modulo 2^32."
//
// "Each message block, M(1), M(2), ..., M(N), is processed in order, using the following steps:
//
//  For i=1 to N:
//  {
//
//
// <TODO>
//
//
//  }
//
//  After repeating steps one through four a total of N times (i.e., after processing M(N)), the resulting
//  256-bit message digest of the message, M, is:
//
//  H0(N) || H1(N) || H2(N) || H3(N) || H4(N) || H5(N) || H6(N) || H7(N)"
