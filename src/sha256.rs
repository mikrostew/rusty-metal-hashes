// sha256 spec is here:
// https://csrc.nist.gov/publications/detail/fips/180/4/final
// (pdf: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

// Note:
//  comments using /* ... */ are text copied from that ^^ hash spec doc,
//  comments using // ... are other comments

/*
   Algorithm   Message Size   Block Size   Word Size   Message Digest Size
                  (bits)        (bits)      (bits)          (bits)

   SHA-256        < 2^64         512          32             256
*/

const WORD_SIZE: usize = 32;
const BLOCK_SIZE_BYTES: usize = 512 / 8;
const BLOCK_SIZE_WORDS: usize = 512 / WORD_SIZE;
const DIGEST_SIZE_BYTES: usize = 256 / 8;

// the output of the sha256 hash function
pub struct Hash {
    digest: [u8; DIGEST_SIZE_BYTES],
}

/*
   Parameters

   The following parameters are used in the secure hash algorithm specifications in this Standard.

    a, b, c, ..., h   Working variables that are the w-bit words used in the computation of the hash values, H(i)

    H(i)              The i-th hash value. H(0) is the initial hash value; H(N) is the final hash value
                      and is used to determine the message digest.

    Hj(i)             The j-th word of the i-th hash value, where H0(i) is the left-most word of hash value i.

    Kt                Constant value to be used for the iteration t of the hash computation.

    k                 Number of zeroes appended to a message during the padding step.

    l                 Length of the message, M, in bits.

    m                 Number of bits in a message block, M(i).

    M                 Message to be hashed.

    M(i)              Message block i, with a size of m bits.

    Mj(i)             The jth word of the ith message block, where M0(i) is the left-most word of
                      message block i.

    n                 Number of bits to be rotated or shifted when a word is operated upon.

    N                 Number of blocks in the padded message.

    T                 Temporary w-bit word used in the hash computation.

    w                 Number of bits in a word.

    Wt                The t-th w-bit word of the message schedule.
*/

/*
   Symbols and Operations

   The following symbols are used in the secure hash algorithm specifications; each operates on w-bit words.

    ^          Bitwise AND operation.

    ⌄          Bitwise OR ("inclusive-OR") operation.

    ⊕          Bitwise XOR ("exclusive-OR") operation.

    ¬          Bitwise complement operation.

    +          Addition modulo 2^w.

    <<         Left-shift operation, where x << n is obtained by discarding the left-most n
               bits of the word x and then padding the result with n zeroes on the right.

    >>         Right-shift operation, where x >> n is obtained by discarding the right-most
               n bits of the word x and then padding the result with n zeroes on the left.

   The following operations are used in the secure hash algorithm specifications:

    ROTL^n(x)  The rotate left (circular left shift) operation, where x is a w-bit word and n
               is an integer with 0 <= n < w, is defined by ROTL^n(x) = (x << n) ⌄ (x >> w - n).

    ROTR^n(x)  The rotate right (circular right shift) operation, where x is a w-bit word
               and n is an integer with 0 <= n < w, is defined by ROTR^n(x) = (x >> n) ⌄ (x << w - n).

    SHR^n(x)   The right shift operation, where x is a w-bit word and n is an integer with 0 <= n < w,
               is defined by SHR^n(x) = x >> n.
*/
macro_rules! ROTL( ($n:expr, $x:expr) => (($x << $n) | ($x >> (32 - $n))) );
macro_rules! ROTR( ($n:expr, $x:expr) => (($x >> $n) | ($x << (32 - $n))) );
macro_rules! SHR( ($n:expr, $x:expr) => ($x >> $n) );

/*
   SHA-256 [uses] six logical functions, where each function operates on 32-bit words,
   which are represented as x, y, and z. The result of each function is a new 32-bit word."

    Ch(x,y,z)  = (x ^ y) ⊕ (-x ^ z)

    Maj(x,y,z) = (x ^ y) ⊕ (x ^ z) ⊕ (y ^ z)

    Σ0{256}(x) = ROTR^2(x) ⊕ ROTR^13(x) ⊕ ROTR^22(x)

    Σ1{256}(x) = ROTR^6(x) ⊕ ROTR^11(x) ⊕ ROTR^25(x)

    σ0{256}(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕ SHR^3(x)

    σ1{256}(x) = ROTR^17(x) ⊕ ROTR^19(x) ⊕ SHR^10(x)
*/
macro_rules! Ch( ($x:expr, $y:expr, $z:expr) => (($x & $y) ^ (-$x & $z)) );
macro_rules! Maj( ($x:expr, $y:expr, $z:expr) => (($x & $y) ^ ($x & $z) ^ ($y & $z)) );

macro_rules! Sigma0( ($x:expr) => (ROTR!(2, $x) ^ ROTR!(13, $x) ^ ROTR!(22, $x)) );
macro_rules! Sigma1( ($x:expr) => (ROTR!(6, $x) ^ ROTR!(11, $x) ^ ROTR!(25, $x)) );
macro_rules! sigma0( ($x:expr) => (ROTR!(7, $x) ^ ROTR!(18, $x) ^ SHR!(3, $x)) );
macro_rules! sigma1( ($x:expr) => (ROTR!(17, $x) ^ ROTR!(19, $x) ^ SHR!(10, $x)) );

/*
   SHA-256 [uses a] sequence of sixty-four constant 32-bit words,
   K0{256}, K1{256},..., K63{256}.
   These words represent the first thirty-two bits of the fractional parts of
   the cube roots of the first sixty-four prime numbers.
*/
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/*
   Padding the Message

   The purpose of this padding is to ensure that the padded message is a multiple of 512 or 1024
   bits, depending on the algorithm. Padding can be inserted before hash computation begins on a
   message, or at any other time during the hash computation prior to processing the block(s) that
   will contain the padding.

   Suppose that the length of the message, M, is l bits. Append the bit “1” to the end of the
   message, followed by k zero bits, where k is the smallest, non-negative solution to the equation l+1+k = 448 mod 512.
   Then append the 64-bit block that is equal to the number l expressed
   using a binary representation. For example, the (8-bit ASCII) message “abc” has length 8 * 3 = 24,
   so the message is padded with a one bit, then 448-(24+1)=423 zero bits, and then
   the message length, to become the 512-bit padded message:

                                   (423 bits)  (64 bits)
    01100001 01100010 01100011  1  00...00     00...011000
       "a"      "b"      "c"                       l = 24

    The length of the padded message should now be a multiple of 512 bits.
*/
impl Hash {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let h = CpuHasher::new();
        h.push(bytes);
        h.finalize();
        Hash { digest: h.digest() }
    }

    pub fn hex_digest(&self) -> String {
        // TODO: macro-ize this (somehow), taking in the digest length
        format!("{:02x}", self.digest[0] /* , etc... */)
    }
}

/*
   Parsing the Message

   The message and its padding must be parsed into N m-bit blocks.

   For SHA-1, SHA-224 and SHA-256, the message and its padding are parsed into N 512-bit
   blocks, M(1), M(2),..., M(N). Since the 512 bits of the input block may be expressed as sixteen 32-bit
   words, the first 32 bits of message block i are denoted
   M0(i), the next 32 bits are M1(i), and so on up to M15(i).
*/

/*
   Setting the Initial Hash Value (H(0))

   Before hash computation begins for each of the secure hash algorithms, the initial hash value,
   H(0), must be set. The size and number of words in H(0) depends on the message digest size.

   For SHA-256, the initial hash value, H(0), shall consist of the following eight 32-bit words, in hex:

    H0(0) = 6a09e667
    H1(0) = bb67ae85
    H2(0) = 3c6ef372
    H3(0) = a54ff53a
    H4(0) = 510e527f
    H5(0) = 9b05688c
    H6(0) = 1f83d9ab
    H7(0) = 5be0cd19

   These words were obtained by taking the first thirty-two bits of the fractional parts of the square
   roots of the first eight prime numbers.
*/

// this will run the sha256 hash algo on the CPU
pub struct CpuHasher {
    H: [u32; 8],
    buffer: [u32; BLOCK_SIZE_WORDS],
    // total length of input data (in bytes? bits? not sure...)
    data_length: u64,
}

impl CpuHasher {
    fn new() -> Self {
        CpuHasher {
            // initial hash value
            H: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buffer: [0; BLOCK_SIZE_WORDS],
            data_length: 0,
        }
    }

    fn push(&self, bytes: &[u8]) {
        // TODO: copy over the bytes from the data and hash each block
    }

    fn finalize(&self) {
        // TODO: add 0x80, pad with zeros, add the length, and hash the final block
    }

    // provide the digest as a byte array (instead of words)
    fn digest(&self) -> [u8; DIGEST_SIZE_BYTES] {
        // convert these u32 -> u8
        // TODO: macro
        // (also, do I actually have to mask with 0xFF?)
        [
            ((self.H[0] >> 24) & 0xFF) as u8,
            ((self.H[0] >> 16) & 0xFF) as u8,
            ((self.H[0] >> 8) & 0xFF) as u8,
            ((self.H[0]) & 0xFF) as u8,
            ((self.H[1] >> 24) & 0xFF) as u8,
            ((self.H[1] >> 16) & 0xFF) as u8,
            ((self.H[1] >> 8) & 0xFF) as u8,
            ((self.H[1]) & 0xFF) as u8,
            ((self.H[2] >> 24) & 0xFF) as u8,
            ((self.H[2] >> 16) & 0xFF) as u8,
            ((self.H[2] >> 8) & 0xFF) as u8,
            ((self.H[2]) & 0xFF) as u8,
            ((self.H[3] >> 24) & 0xFF) as u8,
            ((self.H[3] >> 16) & 0xFF) as u8,
            ((self.H[3] >> 8) & 0xFF) as u8,
            ((self.H[3]) & 0xFF) as u8,
            ((self.H[4] >> 24) & 0xFF) as u8,
            ((self.H[4] >> 16) & 0xFF) as u8,
            ((self.H[4] >> 8) & 0xFF) as u8,
            ((self.H[4]) & 0xFF) as u8,
            ((self.H[5] >> 24) & 0xFF) as u8,
            ((self.H[5] >> 16) & 0xFF) as u8,
            ((self.H[5] >> 8) & 0xFF) as u8,
            ((self.H[5]) & 0xFF) as u8,
            ((self.H[6] >> 24) & 0xFF) as u8,
            ((self.H[6] >> 16) & 0xFF) as u8,
            ((self.H[6] >> 8) & 0xFF) as u8,
            ((self.H[6]) & 0xFF) as u8,
            ((self.H[7] >> 24) & 0xFF) as u8,
            ((self.H[7] >> 16) & 0xFF) as u8,
            ((self.H[7] >> 8) & 0xFF) as u8,
            ((self.H[7]) & 0xFF) as u8,
        ]
    }
}

/*
   SHA-256

   SHA-256 may be used to hash a message, M, having a length of l bits, where 0 <= l < 2^64.
   The algorithm uses
     1) a message schedule of sixty-four 32-bit words,
     2) eight working variables of 32 bits each, and
     3) a hash value of eight 32-bit words.
   The final result of SHA-256 is a 256-bit message digest.

   The words of the message schedule are labeled W0, W1,..., W63.
   The eight working variables are labeled a, b, c, d, e, f, g, and h.
   The words of the hash value are labeled H0(i), H1(i),..., H7(i),
   which will hold the initial hash value, H(0), replaced by each successive intermediate hash value
   (after each message block is processed), H(i), and ending with the final hash value, H(N).
   SHA-256 also uses two temporary words, T1 and T2.
*/

/*
   SHA-256 Preprocessing

    1. Set the initial hash value, H(0)
    2. The message is padded and parsed
*/

/*
   SHA-256 Hash Computation

   The SHA-256 hash computation uses functions and constants previously defined
   Addition is performed modulo 2^32.

   Each message block, M(1), M(2), ..., M(N), is processed in order, using the following steps:

   For i=1 to N:
   {

     1. Prepare the message schedule, {Wt}:

        for 0 <= t <= 15,  Wt = Mt(i)

        for 16 <= t <= 63,  Wt = σ1{256}(Wt-2) + Wt-7 + σ0{256}(Wt-15) + Wt-16

     2. Initialize the eight working variables, a, b, c, d, e, f, g, and h, with the (i-1)-st hash value:

        a = H0(i-1)
        b = H1(i-1)
        c = H2(i-1)
        d = H3(i-1)
        e = H4(i-1)
        f = H5(i-1)
        g = H6(i-1)
        h = H7(i-1)

     3. For t = 0 to 63:

        T1 = h + Σ1{256}(e) + Kt{256} + Wt
        T2 = Σ0{256}(a) + Maj(a, b, c)
         h = g
         g = f
         f = e
         e = d + T1
         d = c
         c = b
         b = a
         a = T1 + T2

     4. Compute the i-th intermediate hash value H(i):

        H0(i) = a + H0(i-1)
        H1(i) = b + H1(i-1)
        H2(i) = c + H2(i-1)
        H3(i) = d + H3(i-1)
        H4(i) = e + H4(i-1)
        H5(i) = f + H5(i-1)
        H6(i) = g + H6(i-1)
        H7(i) = h + H7(i-1)

   }

   After repeating steps one through four a total of N times (i.e., after processing M(N)), the resulting
   256-bit message digest of the message, M, is:

   H0(N) || H1(N) || H2(N) || H3(N) || H4(N) || H5(N) || H6(N) || H7(N)
*/
macro_rules! iteration0to15( ($t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $W:expr, $M:expr) => (
        // prepare the message schedule
        // TODO, actually, remove this
        $W[$t] = $M[$t];

        // hash computations
        let T1 = $h.wrapping_add(Sigma1!($e)).wrapping_add(K[$t]).wrapping_add($W[$t]);
        let T2 = Sigma0!($a).wrapping_add(Maj!($a, $b, $c));
        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(T1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = T1.wrapping_add(T2);
) );
macro_rules! iteration16to63( ($t:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $W:expr) => (
        // prepare the message schedule
        $W[$t] = sigma1!($W[$t-2]).wrapping_add($W[$t-7]).wrapping_add(sigma0!($W[$t-15])).wrapping_add($W[$t-16]);
        // hash computations
        let T1 = $h.wrapping_add(Sigma1!($e)).wrapping_add(K[$t]).wrapping_add($W[$t]);
        let T2 = Sigma0!($a).wrapping_add(Maj!($a, $b, $c));
        $h = $g;
        $g = $f;
        $f = $e;
        $e = $d.wrapping_add(T1);
        $d = $c;
        $c = $b;
        $b = $a;
        $a = T1.wrapping_add(T2);
) );

impl CpuHasher {
    fn hash_block(&self) {
        let mut a = self.H[0];
        let mut b = self.H[1];
        let mut c = self.H[2];
        let mut d = self.H[3];
        let mut e = self.H[4];
        let mut f = self.H[5];
        let mut g = self.H[6];
        let mut h = self.H[7];

        // TODO: convert the [u8; BLOCK_SIZE_BYTES] -> [u32; BLOCK_SIZE_WORDS] here
        let mut W: [u32; BLOCK_SIZE_WORDS] = [0; BLOCK_SIZE_WORDS];

        // unroll the loop
        iteration0to15!(0, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(1, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(2, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(3, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(4, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(5, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(6, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(7, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(8, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(9, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(10, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(11, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(12, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(13, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(14, a, b, c, d, e, f, g, h, W, self.buffer);
        iteration0to15!(15, a, b, c, d, e, f, g, h, W, self.buffer);

        iteration16to63!(16, a, b, c, d, e, f, g, h, W);
        iteration16to63!(17, a, b, c, d, e, f, g, h, W);
        iteration16to63!(18, a, b, c, d, e, f, g, h, W);
        iteration16to63!(19, a, b, c, d, e, f, g, h, W);
        iteration16to63!(20, a, b, c, d, e, f, g, h, W);
        iteration16to63!(21, a, b, c, d, e, f, g, h, W);
        iteration16to63!(22, a, b, c, d, e, f, g, h, W);
        iteration16to63!(23, a, b, c, d, e, f, g, h, W);
        iteration16to63!(24, a, b, c, d, e, f, g, h, W);
        iteration16to63!(25, a, b, c, d, e, f, g, h, W);
        iteration16to63!(26, a, b, c, d, e, f, g, h, W);
        iteration16to63!(27, a, b, c, d, e, f, g, h, W);
        iteration16to63!(28, a, b, c, d, e, f, g, h, W);
        iteration16to63!(29, a, b, c, d, e, f, g, h, W);
        iteration16to63!(30, a, b, c, d, e, f, g, h, W);
        iteration16to63!(31, a, b, c, d, e, f, g, h, W);
        iteration16to63!(32, a, b, c, d, e, f, g, h, W);
        iteration16to63!(33, a, b, c, d, e, f, g, h, W);
        iteration16to63!(34, a, b, c, d, e, f, g, h, W);
        iteration16to63!(35, a, b, c, d, e, f, g, h, W);
        iteration16to63!(36, a, b, c, d, e, f, g, h, W);
        iteration16to63!(37, a, b, c, d, e, f, g, h, W);
        iteration16to63!(38, a, b, c, d, e, f, g, h, W);
        iteration16to63!(39, a, b, c, d, e, f, g, h, W);
        iteration16to63!(40, a, b, c, d, e, f, g, h, W);
        iteration16to63!(41, a, b, c, d, e, f, g, h, W);
        iteration16to63!(42, a, b, c, d, e, f, g, h, W);
        iteration16to63!(43, a, b, c, d, e, f, g, h, W);
        iteration16to63!(44, a, b, c, d, e, f, g, h, W);
        iteration16to63!(45, a, b, c, d, e, f, g, h, W);
        iteration16to63!(46, a, b, c, d, e, f, g, h, W);
        iteration16to63!(47, a, b, c, d, e, f, g, h, W);
        iteration16to63!(48, a, b, c, d, e, f, g, h, W);
        iteration16to63!(49, a, b, c, d, e, f, g, h, W);
        iteration16to63!(50, a, b, c, d, e, f, g, h, W);
        iteration16to63!(51, a, b, c, d, e, f, g, h, W);
        iteration16to63!(52, a, b, c, d, e, f, g, h, W);
        iteration16to63!(53, a, b, c, d, e, f, g, h, W);
        iteration16to63!(54, a, b, c, d, e, f, g, h, W);
        iteration16to63!(55, a, b, c, d, e, f, g, h, W);
        iteration16to63!(56, a, b, c, d, e, f, g, h, W);
        iteration16to63!(57, a, b, c, d, e, f, g, h, W);
        iteration16to63!(58, a, b, c, d, e, f, g, h, W);
        iteration16to63!(59, a, b, c, d, e, f, g, h, W);
        iteration16to63!(60, a, b, c, d, e, f, g, h, W);
        iteration16to63!(61, a, b, c, d, e, f, g, h, W);
        iteration16to63!(62, a, b, c, d, e, f, g, h, W);
        iteration16to63!(63, a, b, c, d, e, f, g, h, W);

        self.H[0] = self.H[0].wrapping_add(a);
        self.H[1] = self.H[0].wrapping_add(b);
        self.H[2] = self.H[0].wrapping_add(c);
        self.H[3] = self.H[0].wrapping_add(d);
        self.H[4] = self.H[0].wrapping_add(e);
        self.H[5] = self.H[0].wrapping_add(f);
        self.H[6] = self.H[0].wrapping_add(g);
        self.H[7] = self.H[0].wrapping_add(h);
    }
}
