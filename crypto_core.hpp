/**
 * crypto_core.hpp  —  Research-Grade Encryption Visualizer
 * Full internal-state capture for cryptanalysis, side-channel simulation,
 * differential analysis, and statistical testing.
 *
 * Algorithms: AES-128/192/256 (ECB/CBC/CTR/GCM), ChaCha20-Poly1305,
 *             SHA-256, SHA-3 (Keccak-256/512), HMAC-SHA256, PBKDF2-HMAC-SHA256,
 *             RSA (PKCS#1 v1.5), DH, XOR, Vigenère
 *
 * Analysis:   Avalanche, Differential Cryptanalysis (AES), Linear Approximation,
 *             Timing Side-Channel Simulation, Hamming-Weight Power Trace (CPA),
 *             NIST SP 800-22 subset statistical tests, Strict Avalanche Criterion
 */
#pragma once
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

// ── AES ──────────────────────────────────────────────────────────────────────

struct AESRoundState {
    int         round;
    std::string operation;
    std::string state_before;
    std::string after_sub_bytes;
    std::string after_shift_rows;
    std::string after_mix_columns;
    std::string after_add_round_key;
    std::string subkey;
    // Research fields
    std::vector<int>    active_sboxes;      // indices of non-zero input bytes
    std::vector<double> hw_distribution;    // Hamming-weight per byte
    std::vector<int>    differential_mask;  // XOR diff propagation vs prev round
};

struct AESResult {
    std::string algorithm, mode, ciphertext_hex;
    std::string iv_hex;                     // CBC/CTR/GCM
    std::string tag_hex;                    // GCM auth tag
    std::vector<AESRoundState>  rounds;
    std::vector<std::string>    key_schedule;
    std::vector<std::string>    sbox_hex;
    // Research fields
    std::vector<double>         round_avalanche;   // per-round bit change ratio
    std::vector<int>            hw_trace;          // Hamming-weight power trace
    double                      strict_avalanche;  // SAC score 0.0–1.0
    int                         num_active_sboxes; // differential trail weight
};

// ── AES modes ─────────────────────────────────────────────────────────────────

AESResult aes_encrypt_visualize(const std::string& pt_hex,
                                 const std::string& key_hex,
                                 const std::string& mode = "ECB",
                                 const std::string& iv_hex = "");

// ── AES Cryptanalysis ─────────────────────────────────────────────────────────

struct DifferentialCharacteristic {
    int  rounds;
    std::string input_diff_hex;
    std::string output_diff_hex;
    double      probability_log2;           // log₂ of differential probability
    std::vector<std::string> round_diffs;   // per-round output differential
    std::vector<int>         active_sboxes; // active S-boxes per round
};

struct LinearApproximation {
    std::string input_mask_hex;
    std::string output_mask_hex;
    double      bias;                       // correlation bias ε
    double      advantage;                  // |ε|
    std::vector<double> round_biases;
};

struct SACResult {
    double       sac_score;                 // 0.0–1.0 (ideal = 0.5)
    std::vector<std::vector<double>> bit_matrix; // 128×128 flip probabilities
    std::vector<double> per_bit_avalanche;
    int          samples_used;
};

struct PowerTraceResult {
    std::string  algorithm;
    std::vector<int>    hamming_weights;    // HW per operation
    std::vector<double> power_samples;      // simulated power (HW + noise)
    std::vector<int>    operation_labels;   // which op each sample belongs to
    // CPA (Correlation Power Analysis) results
    std::vector<std::vector<double>> cpa_correlation; // key_byte × time_sample
    std::vector<int>    cpa_key_guess;      // best key byte guess per position
};

DifferentialCharacteristic aes_differential_trail(const std::string& pt1_hex,
                                                   const std::string& pt2_hex,
                                                   const std::string& key_hex,
                                                   int num_rounds = 4);

LinearApproximation aes_linear_approximation(const std::string& input_mask_hex,
                                              const std::string& output_mask_hex,
                                              int num_rounds = 3);

SACResult aes_strict_avalanche(const std::string& key_hex,
                                int num_samples = 1000);

PowerTraceResult aes_power_trace(const std::string& pt_hex,
                                  const std::string& key_hex,
                                  double noise_sigma = 0.1);

// ── ChaCha20 / Poly1305 ───────────────────────────────────────────────────────

struct ChaCha20Round {
    int round_number;
    std::string type;   // "column" | "diagonal"
    std::vector<std::string> state_before, state_after;
    std::vector<int>    qr_indices;         // which 4 words changed
    std::vector<double> hw_per_word;        // Hamming-weight per word
};

struct Poly1305Result {
    std::string tag_hex;
    std::string r_hex, s_hex;
    std::vector<std::string> accumulator_states;
};

struct ChaCha20Result {
    std::string algorithm, ciphertext_hex, keystream_hex;
    std::vector<std::string> initial_state, final_keystream_state;
    std::vector<ChaCha20Round> rounds;
    Poly1305Result poly1305;
    bool has_poly1305;
};

ChaCha20Result chacha20_encrypt_visualize(const std::string& pt_hex,
                                           const std::string& key_hex,
                                           const std::string& nonce_hex,
                                           uint32_t counter = 0,
                                           bool with_poly1305 = false,
                                           const std::string& aad_hex = "");

// ── SHA-256 ───────────────────────────────────────────────────────────────────

struct SHA256RoundStep {
    int      round;
    uint32_t a,b,c,d,e,f,g,h;
    uint32_t W, K, T1, T2;
    uint32_t a_new, e_new;
    // Research fields
    int      hw_T1, hw_T2;                 // Hamming weight of temporaries
    uint32_t sigma0, sigma1;               // expansion sigmas
    uint32_t ch_val, maj_val;              // Ch and Maj function outputs
};

struct SHA256Block {
    int block_index;
    std::vector<std::string>    message_schedule;
    std::vector<std::string>    initial_working;
    std::vector<SHA256RoundStep> steps;
    std::vector<std::string>    final_hash;
    // Research
    std::vector<int>            schedule_hw;   // HW of each W[i]
};

struct SHA256Result {
    std::string algorithm, digest_hex, padded_message_hex;
    size_t      num_blocks;
    std::vector<std::string> initial_hash;
    std::vector<SHA256Block> blocks;
    // Research
    double      compression_avalanche;     // avg bit change per round
    std::string length_extension_demo;    // shows length-extension vulnerability
};

SHA256Result sha256_visualize(const std::string& msg_hex);

// ── SHA-3 / Keccak ────────────────────────────────────────────────────────────

struct KeccakRound {
    int round_number;
    std::vector<std::string> state_before;  // 25 lanes as hex
    std::vector<std::string> state_after;
    std::string theta_xors;
    std::string rho_shifts;
    std::string pi_permutation;
    std::string chi_nonlinear;
    std::string iota_constant;
};

struct SHA3Result {
    std::string algorithm;      // "SHA3-256" | "SHA3-512" | "SHAKE128" | "SHAKE256"
    std::string digest_hex;
    std::string rate_hex;
    std::string capacity_hex;
    int rate_bits, capacity_bits;
    std::vector<KeccakRound> rounds;
    std::vector<std::string> absorption_states;
    std::vector<std::string> squeezing_states;
};

SHA3Result sha3_visualize(const std::string& msg_hex,
                           const std::string& variant = "SHA3-256");

// ── HMAC ─────────────────────────────────────────────────────────────────────

struct HMACResult {
    std::string algorithm;
    std::string mac_hex;
    std::string ipad_key_hex, opad_key_hex;
    std::string inner_hash_hex, outer_hash_hex;
    SHA256Result inner_sha, outer_sha;
};

HMACResult hmac_sha256_visualize(const std::string& key_hex,
                                  const std::string& msg_hex);

// ── PBKDF2 ───────────────────────────────────────────────────────────────────

struct PBKDF2Round {
    int          iteration;
    std::string  u_hex;     // PRF output for this iteration
    std::string  t_hex;     // accumulated XOR
};

struct PBKDF2Result {
    std::string  algorithm;
    std::string  derived_key_hex;
    std::string  salt_hex;
    int          iterations, dklen;
    std::vector<PBKDF2Round> rounds;
    double       entropy_bits;
    long long    estimated_crack_time_ms; // at 1B guesses/sec
};

PBKDF2Result pbkdf2_visualize(const std::string& password_hex,
                               const std::string& salt_hex,
                               int iterations = 10000,
                               int dklen = 32);

// ── RSA ───────────────────────────────────────────────────────────────────────

struct ModExpStep {
    uint64_t result_before, base_squared, result_after, exponent_bit, modulus;
    int      hw_result;   // Hamming weight — timing side-channel indicator
};

struct RSAOperation {
    uint64_t plaintext_num, ciphertext_num, decrypted_num;
    std::vector<ModExpStep> encrypt_steps;
    std::vector<int>        timing_trace;  // simulated timing per bit
};

struct RSAResult {
    std::string algorithm;
    uint64_t p, q, n, phi_n, e, d;
    bool     p_prime_verified, q_prime_verified; // Miller-Rabin
    int      p_miller_rabin_rounds, q_miller_rabin_rounds;
    std::vector<RSAOperation> operations;
    // Attacks
    std::string wiener_attack_result;     // "vulnerable" | "safe"
    double      fermat_factoring_steps;   // if p,q too close
    std::vector<int> timing_side_channel;
    std::string pohlig_hellman_structure;
    int         security_bits;
};

RSAResult rsa_visualize(uint64_t p, uint64_t q, uint64_t e,
                         const std::string& msg_hex);

// ── DH ───────────────────────────────────────────────────────────────────────

struct DLogStep { uint64_t x, val; };

struct DHResult {
    std::string algorithm;
    uint64_t    prime, generator;
    uint64_t    alice_private, alice_public;
    uint64_t    bob_private,   bob_public;
    uint64_t    alice_shared,  bob_shared;
    std::vector<DLogStep> dlog_steps;
    // Research
    bool        small_subgroup_vulnerable;
    std::string pohlig_hellman_structure;  // factorization of p-1
    int         security_bits;             // estimated DL security
};

DHResult dh_visualize(uint64_t p, uint64_t g,
                       uint64_t alice_priv, uint64_t bob_priv);

// ── XOR ──────────────────────────────────────────────────────────────────────

struct XORStep {
    int index;
    uint8_t pt_byte, key_byte, ct_byte;
    std::string pt_bits, key_bits, ct_bits;
    int hw_pt, hw_ct;   // Hamming weights
};

struct XORResult {
    std::string algorithm;
    std::string plaintext_bits, key_bits, key_repeated_hex;
    std::string ciphertext_bits, ciphertext_hex;
    std::vector<XORStep> steps;
    double      key_entropy;    // Shannon entropy of key bytes
    double      ic;             // Index of Coincidence of ciphertext
};

XORResult xor_visualize(const std::string& pt_hex, const std::string& key_hex);

// ── Vigenère ─────────────────────────────────────────────────────────────────

struct VigenereStep {
    char plaintext_char, key_char, output_char;
    int  shift;
};

struct VigenereResult {
    std::string algorithm, plaintext, key, ciphertext;
    std::vector<VigenereStep> steps;
    // Cryptanalysis
    double kasiski_key_length_estimate;
    std::vector<std::pair<int,double>> ioc_by_keylength; // (len, IoC)
    std::vector<std::string> recovered_key_bytes;        // frequency-recovered
};

VigenereResult vigenere_visualize(const std::string& plaintext,
                                   const std::string& key,
                                   bool encrypt = true);

// ── NIST Statistical Tests ────────────────────────────────────────────────────

struct NISTTestResult {
    std::string test_name;
    double      p_value;
    bool        passed;         // p_value >= 0.01
    std::string interpretation;
    std::map<std::string,double> details;
};

struct NISTSuiteResult {
    std::vector<NISTTestResult> tests;
    int    passed_count, total_count;
    double overall_score;       // fraction passed
    bool   is_random;           // passed >= 95% tests
};

NISTSuiteResult nist_statistical_tests(const std::string& bitstream_hex,
                                        int num_bits = 0); // 0 = use all

// ── Challenge Generator ───────────────────────────────────────────────────────

struct CryptoChallenge {
    std::string id, algorithm, difficulty;
    std::string category;     // "classical"|"symmetric"|"asymmetric"|"hash"|"sidechannel"|"cryptanalysis"
    std::string question, hint, solution_approach;
    std::string plaintext_hex, key_hex, ciphertext_hex;
    std::string expected_answer;
    int         points;
    std::string reference;    // NIST / RFC / paper citation
};

CryptoChallenge generate_challenge(const std::string& algorithm,
                                   const std::string& difficulty);
