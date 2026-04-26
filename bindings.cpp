/**
 * bindings.cpp  —  Research-Grade Encryption Visualizer
 * pybind11 bindings: exposes every struct and function to Python.
 */
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "crypto_core.hpp"
namespace py = pybind11;

// ── Generic dict helpers ──────────────────────────────────────────────────────
static py::dict aes_round_to_dict(const AESRoundState& r){
    py::dict d;
    d["round"]=r.round; d["operation"]=r.operation;
    d["state_before"]=r.state_before; d["after_sub_bytes"]=r.after_sub_bytes;
    d["after_shift_rows"]=r.after_shift_rows; d["after_mix_columns"]=r.after_mix_columns;
    d["after_add_round_key"]=r.after_add_round_key; d["subkey"]=r.subkey;
    d["active_sboxes"]=r.active_sboxes; d["hw_distribution"]=r.hw_distribution;
    d["differential_mask"]=r.differential_mask;
    return d;
}

PYBIND11_MODULE(crypto_engine, m){
    m.doc()="Research-Grade Encryption Visualizer — C++ Core via pybind11";

    // ── AES ──────────────────────────────────────────────────────────────────
    py::class_<AESRoundState>(m,"AESRoundState")
        .def_readonly("round",&AESRoundState::round)
        .def_readonly("operation",&AESRoundState::operation)
        .def_readonly("state_before",&AESRoundState::state_before)
        .def_readonly("after_sub_bytes",&AESRoundState::after_sub_bytes)
        .def_readonly("after_shift_rows",&AESRoundState::after_shift_rows)
        .def_readonly("after_mix_columns",&AESRoundState::after_mix_columns)
        .def_readonly("after_add_round_key",&AESRoundState::after_add_round_key)
        .def_readonly("subkey",&AESRoundState::subkey)
        .def_readonly("active_sboxes",&AESRoundState::active_sboxes)
        .def_readonly("hw_distribution",&AESRoundState::hw_distribution)
        .def_readonly("differential_mask",&AESRoundState::differential_mask);

    py::class_<AESResult>(m,"AESResult")
        .def_readonly("algorithm",&AESResult::algorithm)
        .def_readonly("mode",&AESResult::mode)
        .def_readonly("ciphertext_hex",&AESResult::ciphertext_hex)
        .def_readonly("iv_hex",&AESResult::iv_hex)
        .def_readonly("tag_hex",&AESResult::tag_hex)
        .def_readonly("rounds",&AESResult::rounds)
        .def_readonly("key_schedule",&AESResult::key_schedule)
        .def_readonly("sbox_hex",&AESResult::sbox_hex)
        .def_readonly("round_avalanche",&AESResult::round_avalanche)
        .def_readonly("hw_trace",&AESResult::hw_trace)
        .def_readonly("strict_avalanche",&AESResult::strict_avalanche)
        .def_readonly("num_active_sboxes",&AESResult::num_active_sboxes)
        .def("to_dict",[](const AESResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["mode"]=r.mode;
            d["ciphertext_hex"]=r.ciphertext_hex; d["iv_hex"]=r.iv_hex; d["tag_hex"]=r.tag_hex;
            d["key_schedule"]=r.key_schedule; d["sbox_hex"]=r.sbox_hex;
            d["round_avalanche"]=r.round_avalanche; d["hw_trace"]=r.hw_trace;
            d["strict_avalanche"]=r.strict_avalanche;
            d["num_active_sboxes"]=r.num_active_sboxes;
            py::list rounds;
            for(auto& rs:r.rounds) rounds.append(aes_round_to_dict(rs));
            d["rounds"]=rounds; return d;
        });

    m.def("aes_encrypt_visualize",&aes_encrypt_visualize,
          py::arg("pt_hex"),py::arg("key_hex"),py::arg("mode")="ECB",py::arg("iv_hex")="",
          "AES encrypt with full per-round state (ECB/CBC/CTR/GCM)");

    // ── AES Cryptanalysis ─────────────────────────────────────────────────────
    py::class_<DifferentialCharacteristic>(m,"DifferentialCharacteristic")
        .def_readonly("rounds",&DifferentialCharacteristic::rounds)
        .def_readonly("input_diff_hex",&DifferentialCharacteristic::input_diff_hex)
        .def_readonly("output_diff_hex",&DifferentialCharacteristic::output_diff_hex)
        .def_readonly("probability_log2",&DifferentialCharacteristic::probability_log2)
        .def_readonly("round_diffs",&DifferentialCharacteristic::round_diffs)
        .def_readonly("active_sboxes",&DifferentialCharacteristic::active_sboxes)
        .def("to_dict",[](const DifferentialCharacteristic& dc){
            py::dict d;
            d["rounds"]=dc.rounds; d["input_diff_hex"]=dc.input_diff_hex;
            d["output_diff_hex"]=dc.output_diff_hex;
            d["probability_log2"]=dc.probability_log2;
            d["round_diffs"]=dc.round_diffs; d["active_sboxes"]=dc.active_sboxes;
            return d;
        });

    py::class_<LinearApproximation>(m,"LinearApproximation")
        .def_readonly("input_mask_hex",&LinearApproximation::input_mask_hex)
        .def_readonly("output_mask_hex",&LinearApproximation::output_mask_hex)
        .def_readonly("bias",&LinearApproximation::bias)
        .def_readonly("advantage",&LinearApproximation::advantage)
        .def_readonly("round_biases",&LinearApproximation::round_biases)
        .def("to_dict",[](const LinearApproximation& la){
            py::dict d;
            d["input_mask_hex"]=la.input_mask_hex; d["output_mask_hex"]=la.output_mask_hex;
            d["bias"]=la.bias; d["advantage"]=la.advantage; d["round_biases"]=la.round_biases;
            return d;
        });

    py::class_<SACResult>(m,"SACResult")
        .def_readonly("sac_score",&SACResult::sac_score)
        .def_readonly("bit_matrix",&SACResult::bit_matrix)
        .def_readonly("per_bit_avalanche",&SACResult::per_bit_avalanche)
        .def_readonly("samples_used",&SACResult::samples_used)
        .def("to_dict",[](const SACResult& s){
            py::dict d;
            d["sac_score"]=s.sac_score; d["bit_matrix"]=s.bit_matrix;
            d["per_bit_avalanche"]=s.per_bit_avalanche; d["samples_used"]=s.samples_used;
            return d;
        });

    py::class_<PowerTraceResult>(m,"PowerTraceResult")
        .def_readonly("algorithm",&PowerTraceResult::algorithm)
        .def_readonly("hamming_weights",&PowerTraceResult::hamming_weights)
        .def_readonly("power_samples",&PowerTraceResult::power_samples)
        .def_readonly("operation_labels",&PowerTraceResult::operation_labels)
        .def_readonly("cpa_correlation",&PowerTraceResult::cpa_correlation)
        .def_readonly("cpa_key_guess",&PowerTraceResult::cpa_key_guess)
        .def("to_dict",[](const PowerTraceResult& p){
            py::dict d;
            d["algorithm"]=p.algorithm; d["hamming_weights"]=p.hamming_weights;
            d["power_samples"]=p.power_samples; d["operation_labels"]=p.operation_labels;
            d["cpa_key_guess"]=p.cpa_key_guess;
            // cpa_correlation is large; truncate to first 4 key guesses
            py::list cpa;
            for(int i=0;i<4&&i<(int)p.cpa_correlation.size();++i){
                py::list row;
                for(int j=0;j<(int)p.cpa_correlation[i].size()&&j<64;++j) row.append(p.cpa_correlation[i][j]);
                cpa.append(row);
            }
            d["cpa_correlation"]=cpa; return d;
        });

    m.def("aes_differential_trail",&aes_differential_trail,
          py::arg("pt1_hex"),py::arg("pt2_hex"),py::arg("key_hex"),py::arg("num_rounds")=4,
          "AES differential characteristic: input→output differential with probability");
    m.def("aes_linear_approximation",&aes_linear_approximation,
          py::arg("input_mask_hex"),py::arg("output_mask_hex"),py::arg("num_rounds")=3,
          "AES linear approximation: bias and piling-up lemma over rounds");
    m.def("aes_strict_avalanche",&aes_strict_avalanche,
          py::arg("key_hex"),py::arg("num_samples")=256,
          "Strict Avalanche Criterion: 128×128 bit-flip matrix");
    m.def("aes_power_trace",&aes_power_trace,
          py::arg("pt_hex"),py::arg("key_hex"),py::arg("noise_sigma")=0.1,
          "Simulated HW power trace + CPA key recovery");

    // ── ChaCha20 ─────────────────────────────────────────────────────────────
    py::class_<Poly1305Result>(m,"Poly1305Result")
        .def_readonly("tag_hex",&Poly1305Result::tag_hex)
        .def_readonly("r_hex",&Poly1305Result::r_hex)
        .def_readonly("s_hex",&Poly1305Result::s_hex)
        .def_readonly("accumulator_states",&Poly1305Result::accumulator_states);

    py::class_<ChaCha20Round>(m,"ChaCha20Round")
        .def_readonly("round_number",&ChaCha20Round::round_number)
        .def_readonly("type",&ChaCha20Round::type)
        .def_readonly("state_before",&ChaCha20Round::state_before)
        .def_readonly("state_after",&ChaCha20Round::state_after)
        .def_readonly("qr_indices",&ChaCha20Round::qr_indices)
        .def_readonly("hw_per_word",&ChaCha20Round::hw_per_word);

    py::class_<ChaCha20Result>(m,"ChaCha20Result")
        .def_readonly("algorithm",&ChaCha20Result::algorithm)
        .def_readonly("ciphertext_hex",&ChaCha20Result::ciphertext_hex)
        .def_readonly("keystream_hex",&ChaCha20Result::keystream_hex)
        .def_readonly("initial_state",&ChaCha20Result::initial_state)
        .def_readonly("final_keystream_state",&ChaCha20Result::final_keystream_state)
        .def_readonly("rounds",&ChaCha20Result::rounds)
        .def_readonly("poly1305",&ChaCha20Result::poly1305)
        .def_readonly("has_poly1305",&ChaCha20Result::has_poly1305)
        .def("to_dict",[](const ChaCha20Result& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["ciphertext_hex"]=r.ciphertext_hex;
            d["keystream_hex"]=r.keystream_hex; d["initial_state"]=r.initial_state;
            d["final_keystream_state"]=r.final_keystream_state;
            d["has_poly1305"]=r.has_poly1305;
            if(r.has_poly1305){
                py::dict pd;
                pd["tag_hex"]=r.poly1305.tag_hex; pd["r_hex"]=r.poly1305.r_hex;
                pd["s_hex"]=r.poly1305.s_hex; pd["accumulator_states"]=r.poly1305.accumulator_states;
                d["poly1305"]=pd;
            }
            py::list rounds;
            for(auto& cr:r.rounds){
                py::dict rd;
                rd["round_number"]=cr.round_number; rd["type"]=cr.type;
                rd["state_before"]=cr.state_before; rd["state_after"]=cr.state_after;
                rd["qr_indices"]=cr.qr_indices; rd["hw_per_word"]=cr.hw_per_word;
                rounds.append(rd);
            }
            d["rounds"]=rounds; return d;
        });

    m.def("chacha20_encrypt_visualize",&chacha20_encrypt_visualize,
          py::arg("pt_hex"),py::arg("key_hex"),py::arg("nonce_hex"),
          py::arg("counter")=0u,py::arg("with_poly1305")=false,py::arg("aad_hex")="",
          "ChaCha20(-Poly1305) with full quarter-round state and HW trace");

    // ── SHA-256 ──────────────────────────────────────────────────────────────
    py::class_<SHA256RoundStep>(m,"SHA256RoundStep")
        .def_readonly("round",&SHA256RoundStep::round)
        .def_readonly("a",&SHA256RoundStep::a).def_readonly("b",&SHA256RoundStep::b)
        .def_readonly("c",&SHA256RoundStep::c).def_readonly("d",&SHA256RoundStep::d)
        .def_readonly("e",&SHA256RoundStep::e).def_readonly("f",&SHA256RoundStep::f)
        .def_readonly("g",&SHA256RoundStep::g).def_readonly("h",&SHA256RoundStep::h)
        .def_readonly("W",&SHA256RoundStep::W).def_readonly("K",&SHA256RoundStep::K)
        .def_readonly("T1",&SHA256RoundStep::T1).def_readonly("T2",&SHA256RoundStep::T2)
        .def_readonly("a_new",&SHA256RoundStep::a_new).def_readonly("e_new",&SHA256RoundStep::e_new)
        .def_readonly("hw_T1",&SHA256RoundStep::hw_T1).def_readonly("hw_T2",&SHA256RoundStep::hw_T2)
        .def_readonly("sigma0",&SHA256RoundStep::sigma0).def_readonly("sigma1",&SHA256RoundStep::sigma1)
        .def_readonly("ch_val",&SHA256RoundStep::ch_val).def_readonly("maj_val",&SHA256RoundStep::maj_val);

    py::class_<SHA256Block>(m,"SHA256Block")
        .def_readonly("block_index",&SHA256Block::block_index)
        .def_readonly("message_schedule",&SHA256Block::message_schedule)
        .def_readonly("initial_working",&SHA256Block::initial_working)
        .def_readonly("steps",&SHA256Block::steps)
        .def_readonly("final_hash",&SHA256Block::final_hash)
        .def_readonly("schedule_hw",&SHA256Block::schedule_hw);

    py::class_<SHA256Result>(m,"SHA256Result")
        .def_readonly("algorithm",&SHA256Result::algorithm)
        .def_readonly("digest_hex",&SHA256Result::digest_hex)
        .def_readonly("padded_message_hex",&SHA256Result::padded_message_hex)
        .def_readonly("num_blocks",&SHA256Result::num_blocks)
        .def_readonly("initial_hash",&SHA256Result::initial_hash)
        .def_readonly("blocks",&SHA256Result::blocks)
        .def_readonly("compression_avalanche",&SHA256Result::compression_avalanche)
        .def_readonly("length_extension_demo",&SHA256Result::length_extension_demo)
        .def("to_dict",[](const SHA256Result& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["digest_hex"]=r.digest_hex;
            d["padded_message_hex"]=r.padded_message_hex; d["num_blocks"]=r.num_blocks;
            d["initial_hash"]=r.initial_hash;
            d["compression_avalanche"]=r.compression_avalanche;
            d["length_extension_demo"]=r.length_extension_demo;
            py::list blocks;
            for(auto& b:r.blocks){
                py::dict bd;
                bd["block_index"]=b.block_index; bd["message_schedule"]=b.message_schedule;
                bd["initial_working"]=b.initial_working; bd["final_hash"]=b.final_hash;
                bd["schedule_hw"]=b.schedule_hw;
                py::list steps;
                for(auto& s:b.steps){
                    py::dict sd;
                    sd["round"]=s.round;
                    sd["a"]=s.a;sd["b"]=s.b;sd["c"]=s.c;sd["d"]=s.d;
                    sd["e"]=s.e;sd["f"]=s.f;sd["g"]=s.g;sd["h"]=s.h;
                    sd["W"]=s.W;sd["K"]=s.K;sd["T1"]=s.T1;sd["T2"]=s.T2;
                    sd["a_new"]=s.a_new;sd["e_new"]=s.e_new;
                    sd["hw_T1"]=s.hw_T1;sd["hw_T2"]=s.hw_T2;
                    sd["sigma0"]=s.sigma0;sd["sigma1"]=s.sigma1;
                    sd["ch_val"]=s.ch_val;sd["maj_val"]=s.maj_val;
                    steps.append(sd);
                }
                bd["steps"]=steps; blocks.append(bd);
            }
            d["blocks"]=blocks; return d;
        });

    m.def("sha256_visualize",&sha256_visualize,py::arg("msg_hex"),
          "SHA-256 with full compression function, schedule HW, and length-extension demo");

    // ── SHA-3 ─────────────────────────────────────────────────────────────────
    py::class_<KeccakRound>(m,"KeccakRound")
        .def_readonly("round_number",&KeccakRound::round_number)
        .def_readonly("state_before",&KeccakRound::state_before)
        .def_readonly("state_after",&KeccakRound::state_after)
        .def_readonly("theta_xors",&KeccakRound::theta_xors)
        .def_readonly("iota_constant",&KeccakRound::iota_constant);

    py::class_<SHA3Result>(m,"SHA3Result")
        .def_readonly("algorithm",&SHA3Result::algorithm)
        .def_readonly("digest_hex",&SHA3Result::digest_hex)
        .def_readonly("rate_bits",&SHA3Result::rate_bits)
        .def_readonly("capacity_bits",&SHA3Result::capacity_bits)
        .def_readonly("rounds",&SHA3Result::rounds)
        .def_readonly("absorption_states",&SHA3Result::absorption_states)
        .def_readonly("squeezing_states",&SHA3Result::squeezing_states)
        .def("to_dict",[](const SHA3Result& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["digest_hex"]=r.digest_hex;
            d["rate_bits"]=r.rate_bits; d["capacity_bits"]=r.capacity_bits;
            d["absorption_states"]=r.absorption_states; d["squeezing_states"]=r.squeezing_states;
            py::list rounds;
            for(auto& kr:r.rounds){
                py::dict rd;
                rd["round_number"]=kr.round_number;
                rd["state_before"]=kr.state_before; rd["state_after"]=kr.state_after;
                rd["theta_xors"]=kr.theta_xors; rd["iota_constant"]=kr.iota_constant;
                rounds.append(rd);
            }
            d["rounds"]=rounds; return d;
        });

    m.def("sha3_visualize",&sha3_visualize,
          py::arg("msg_hex"),py::arg("variant")="SHA3-256",
          "SHA-3 (Keccak) with full sponge absorption/squeezing and round state");

    // ── HMAC ─────────────────────────────────────────────────────────────────
    py::class_<HMACResult>(m,"HMACResult")
        .def_readonly("algorithm",&HMACResult::algorithm)
        .def_readonly("mac_hex",&HMACResult::mac_hex)
        .def_readonly("ipad_key_hex",&HMACResult::ipad_key_hex)
        .def_readonly("opad_key_hex",&HMACResult::opad_key_hex)
        .def_readonly("inner_hash_hex",&HMACResult::inner_hash_hex)
        .def_readonly("outer_hash_hex",&HMACResult::outer_hash_hex)
        .def("to_dict",[](const HMACResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["mac_hex"]=r.mac_hex;
            d["ipad_key_hex"]=r.ipad_key_hex; d["opad_key_hex"]=r.opad_key_hex;
            d["inner_hash_hex"]=r.inner_hash_hex; d["outer_hash_hex"]=r.outer_hash_hex;
            return d;
        });

    m.def("hmac_sha256_visualize",&hmac_sha256_visualize,
          py::arg("key_hex"),py::arg("msg_hex"),
          "HMAC-SHA256: ipad/opad key derivation, inner and outer hash visualization");

    // ── PBKDF2 ───────────────────────────────────────────────────────────────
    py::class_<PBKDF2Round>(m,"PBKDF2Round")
        .def_readonly("iteration",&PBKDF2Round::iteration)
        .def_readonly("u_hex",&PBKDF2Round::u_hex)
        .def_readonly("t_hex",&PBKDF2Round::t_hex);

    py::class_<PBKDF2Result>(m,"PBKDF2Result")
        .def_readonly("algorithm",&PBKDF2Result::algorithm)
        .def_readonly("derived_key_hex",&PBKDF2Result::derived_key_hex)
        .def_readonly("salt_hex",&PBKDF2Result::salt_hex)
        .def_readonly("iterations",&PBKDF2Result::iterations)
        .def_readonly("dklen",&PBKDF2Result::dklen)
        .def_readonly("rounds",&PBKDF2Result::rounds)
        .def_readonly("entropy_bits",&PBKDF2Result::entropy_bits)
        .def_readonly("estimated_crack_time_ms",&PBKDF2Result::estimated_crack_time_ms)
        .def("to_dict",[](const PBKDF2Result& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["derived_key_hex"]=r.derived_key_hex;
            d["salt_hex"]=r.salt_hex; d["iterations"]=r.iterations; d["dklen"]=r.dklen;
            d["entropy_bits"]=r.entropy_bits; d["estimated_crack_time_ms"]=r.estimated_crack_time_ms;
            py::list rounds;
            for(auto& pr:r.rounds){ py::dict rd; rd["iteration"]=pr.iteration; rd["u_hex"]=pr.u_hex; rd["t_hex"]=pr.t_hex; rounds.append(rd); }
            d["rounds"]=rounds; return d;
        });

    m.def("pbkdf2_visualize",&pbkdf2_visualize,
          py::arg("password_hex"),py::arg("salt_hex"),
          py::arg("iterations")=10000,py::arg("dklen")=32,
          "PBKDF2-HMAC-SHA256 with iteration trace and crack-time estimate");

    // ── RSA ──────────────────────────────────────────────────────────────────
    py::class_<ModExpStep>(m,"ModExpStep")
        .def_readonly("result_before",&ModExpStep::result_before)
        .def_readonly("base_squared",&ModExpStep::base_squared)
        .def_readonly("result_after",&ModExpStep::result_after)
        .def_readonly("exponent_bit",&ModExpStep::exponent_bit)
        .def_readonly("modulus",&ModExpStep::modulus)
        .def_readonly("hw_result",&ModExpStep::hw_result);

    py::class_<RSAOperation>(m,"RSAOperation")
        .def_readonly("plaintext_num",&RSAOperation::plaintext_num)
        .def_readonly("ciphertext_num",&RSAOperation::ciphertext_num)
        .def_readonly("decrypted_num",&RSAOperation::decrypted_num)
        .def_readonly("encrypt_steps",&RSAOperation::encrypt_steps)
        .def_readonly("timing_trace",&RSAOperation::timing_trace);

    py::class_<RSAResult>(m,"RSAResult")
        .def_readonly("algorithm",&RSAResult::algorithm)
        .def_readonly("p",&RSAResult::p).def_readonly("q",&RSAResult::q)
        .def_readonly("n",&RSAResult::n).def_readonly("phi_n",&RSAResult::phi_n)
        .def_readonly("e",&RSAResult::e).def_readonly("d",&RSAResult::d)
        .def_readonly("p_prime_verified",&RSAResult::p_prime_verified)
        .def_readonly("q_prime_verified",&RSAResult::q_prime_verified)
        .def_readonly("p_miller_rabin_rounds",&RSAResult::p_miller_rabin_rounds)
        .def_readonly("wiener_attack_result",&RSAResult::wiener_attack_result)
        .def_readonly("fermat_factoring_steps",&RSAResult::fermat_factoring_steps)
        .def_readonly("security_bits",&RSAResult::security_bits)
        .def_readonly("operations",&RSAResult::operations)
        .def_readonly("timing_side_channel",&RSAResult::timing_side_channel)
        .def("to_dict",[](const RSAResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm;
            d["p"]=r.p;d["q"]=r.q;d["n"]=r.n;d["phi_n"]=r.phi_n;d["e"]=r.e;d["d"]=r.d;
            d["p_prime_verified"]=r.p_prime_verified; d["q_prime_verified"]=r.q_prime_verified;
            d["p_miller_rabin_rounds"]=r.p_miller_rabin_rounds;
            d["wiener_attack_result"]=r.wiener_attack_result;
            d["fermat_factoring_steps"]=r.fermat_factoring_steps;
            d["security_bits"]=r.security_bits;
            d["timing_side_channel"]=r.timing_side_channel;
            py::list ops;
            for(auto& op:r.operations){
                py::dict od;
                od["plaintext_num"]=op.plaintext_num; od["ciphertext_num"]=op.ciphertext_num;
                od["decrypted_num"]=op.decrypted_num; od["timing_trace"]=op.timing_trace;
                py::list steps;
                for(auto& s:op.encrypt_steps){
                    py::dict sd;
                    sd["result_before"]=s.result_before; sd["base_squared"]=s.base_squared;
                    sd["result_after"]=s.result_after; sd["exponent_bit"]=s.exponent_bit;
                    sd["modulus"]=s.modulus; sd["hw_result"]=s.hw_result;
                    steps.append(sd);
                }
                od["encrypt_steps"]=steps; ops.append(od);
            }
            d["operations"]=ops; return d;
        });

    m.def("rsa_visualize",&rsa_visualize,
          py::arg("p"),py::arg("q"),py::arg("e"),py::arg("msg_hex"),
          "RSA: Miller-Rabin primality, modexp trace, Wiener attack check, timing side-channel");

    // ── DH ───────────────────────────────────────────────────────────────────
    py::class_<DLogStep>(m,"DLogStep")
        .def_readonly("x",&DLogStep::x).def_readonly("val",&DLogStep::val);

    py::class_<DHResult>(m,"DHResult")
        .def_readonly("algorithm",&DHResult::algorithm)
        .def_readonly("prime",&DHResult::prime).def_readonly("generator",&DHResult::generator)
        .def_readonly("alice_private",&DHResult::alice_private).def_readonly("alice_public",&DHResult::alice_public)
        .def_readonly("bob_private",&DHResult::bob_private).def_readonly("bob_public",&DHResult::bob_public)
        .def_readonly("alice_shared",&DHResult::alice_shared).def_readonly("bob_shared",&DHResult::bob_shared)
        .def_readonly("dlog_steps",&DHResult::dlog_steps)
        .def_readonly("small_subgroup_vulnerable",&DHResult::small_subgroup_vulnerable)
        .def_readonly("pohlig_hellman_structure",&DHResult::pohlig_hellman_structure)
        .def_readonly("security_bits",&DHResult::security_bits)
        .def("to_dict",[](const DHResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["prime"]=r.prime; d["generator"]=r.generator;
            d["alice_private"]=r.alice_private; d["alice_public"]=r.alice_public;
            d["bob_private"]=r.bob_private; d["bob_public"]=r.bob_public;
            d["alice_shared"]=r.alice_shared; d["bob_shared"]=r.bob_shared;
            d["small_subgroup_vulnerable"]=r.small_subgroup_vulnerable;
            d["pohlig_hellman_structure"]=r.pohlig_hellman_structure;
            d["security_bits"]=r.security_bits;
            py::list steps;
            for(auto& s:r.dlog_steps){ py::dict sd; sd["x"]=s.x;sd["val"]=s.val; steps.append(sd); }
            d["dlog_steps"]=steps; return d;
        });

    m.def("dh_visualize",&dh_visualize,
          py::arg("p"),py::arg("g"),py::arg("alice_priv"),py::arg("bob_priv"),
          "DH key exchange: dlog brute-force, Pohlig-Hellman group structure, small-subgroup check");

    // ── XOR ──────────────────────────────────────────────────────────────────
    py::class_<XORStep>(m,"XORStep")
        .def_readonly("index",&XORStep::index)
        .def_readonly("pt_byte",&XORStep::pt_byte).def_readonly("key_byte",&XORStep::key_byte)
        .def_readonly("ct_byte",&XORStep::ct_byte)
        .def_readonly("pt_bits",&XORStep::pt_bits).def_readonly("key_bits",&XORStep::key_bits)
        .def_readonly("ct_bits",&XORStep::ct_bits)
        .def_readonly("hw_pt",&XORStep::hw_pt).def_readonly("hw_ct",&XORStep::hw_ct);

    py::class_<XORResult>(m,"XORResult")
        .def_readonly("algorithm",&XORResult::algorithm)
        .def_readonly("plaintext_bits",&XORResult::plaintext_bits)
        .def_readonly("key_bits",&XORResult::key_bits)
        .def_readonly("key_repeated_hex",&XORResult::key_repeated_hex)
        .def_readonly("ciphertext_bits",&XORResult::ciphertext_bits)
        .def_readonly("ciphertext_hex",&XORResult::ciphertext_hex)
        .def_readonly("steps",&XORResult::steps)
        .def_readonly("key_entropy",&XORResult::key_entropy)
        .def_readonly("ic",&XORResult::ic)
        .def("to_dict",[](const XORResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["plaintext_bits"]=r.plaintext_bits;
            d["key_bits"]=r.key_bits; d["key_repeated_hex"]=r.key_repeated_hex;
            d["ciphertext_bits"]=r.ciphertext_bits; d["ciphertext_hex"]=r.ciphertext_hex;
            d["key_entropy"]=r.key_entropy; d["ic"]=r.ic;
            py::list steps;
            for(auto& s:r.steps){
                py::dict sd;
                sd["index"]=s.index; sd["pt_byte"]=(int)s.pt_byte;
                sd["key_byte"]=(int)s.key_byte; sd["ct_byte"]=(int)s.ct_byte;
                sd["pt_bits"]=s.pt_bits; sd["key_bits"]=s.key_bits; sd["ct_bits"]=s.ct_bits;
                sd["hw_pt"]=s.hw_pt; sd["hw_ct"]=s.hw_ct;
                steps.append(sd);
            }
            d["steps"]=steps; return d;
        });

    m.def("xor_visualize",&xor_visualize,py::arg("pt_hex"),py::arg("key_hex"),
          "XOR: bitwise trace, key entropy, ciphertext IoC");

    // ── Vigenère ─────────────────────────────────────────────────────────────
    py::class_<VigenereStep>(m,"VigenereStep")
        .def_readonly("plaintext_char",&VigenereStep::plaintext_char)
        .def_readonly("key_char",&VigenereStep::key_char)
        .def_readonly("output_char",&VigenereStep::output_char)
        .def_readonly("shift",&VigenereStep::shift);

    py::class_<VigenereResult>(m,"VigenereResult")
        .def_readonly("algorithm",&VigenereResult::algorithm)
        .def_readonly("plaintext",&VigenereResult::plaintext)
        .def_readonly("key",&VigenereResult::key)
        .def_readonly("ciphertext",&VigenereResult::ciphertext)
        .def_readonly("steps",&VigenereResult::steps)
        .def_readonly("kasiski_key_length_estimate",&VigenereResult::kasiski_key_length_estimate)
        .def_readonly("ioc_by_keylength",&VigenereResult::ioc_by_keylength)
        .def_readonly("recovered_key_bytes",&VigenereResult::recovered_key_bytes)
        .def("to_dict",[](const VigenereResult& r){
            py::dict d;
            d["algorithm"]=r.algorithm; d["plaintext"]=r.plaintext;
            d["key"]=r.key; d["ciphertext"]=r.ciphertext;
            d["kasiski_key_length_estimate"]=r.kasiski_key_length_estimate;
            d["recovered_key_bytes"]=r.recovered_key_bytes;
            py::list iocs;
            for(auto& kv:r.ioc_by_keylength){ py::list p; p.append(kv.first); p.append(kv.second); iocs.append(p); }
            d["ioc_by_keylength"]=iocs;
            py::list steps;
            for(auto& s:r.steps){
                py::dict sd;
                sd["plaintext_char"]=std::string(1,s.plaintext_char);
                sd["key_char"]=std::string(1,s.key_char);
                sd["output_char"]=std::string(1,s.output_char); sd["shift"]=s.shift;
                steps.append(sd);
            }
            d["steps"]=steps; return d;
        });

    m.def("vigenere_visualize",&vigenere_visualize,
          py::arg("plaintext"),py::arg("key"),py::arg("encrypt")=true,
          "Vigenère: per-char trace, Kasiski analysis, IoC key-length, frequency key recovery");

    // ── NIST Tests ────────────────────────────────────────────────────────────
    py::class_<NISTTestResult>(m,"NISTTestResult")
        .def_readonly("test_name",&NISTTestResult::test_name)
        .def_readonly("p_value",&NISTTestResult::p_value)
        .def_readonly("passed",&NISTTestResult::passed)
        .def_readonly("interpretation",&NISTTestResult::interpretation);

    py::class_<NISTSuiteResult>(m,"NISTSuiteResult")
        .def_readonly("tests",&NISTSuiteResult::tests)
        .def_readonly("passed_count",&NISTSuiteResult::passed_count)
        .def_readonly("total_count",&NISTSuiteResult::total_count)
        .def_readonly("overall_score",&NISTSuiteResult::overall_score)
        .def_readonly("is_random",&NISTSuiteResult::is_random)
        .def("to_dict",[](const NISTSuiteResult& s){
            py::dict d;
            d["passed_count"]=s.passed_count; d["total_count"]=s.total_count;
            d["overall_score"]=s.overall_score; d["is_random"]=s.is_random;
            py::list tests;
            for(auto& t:s.tests){
                py::dict td;
                td["test_name"]=t.test_name; td["p_value"]=t.p_value;
                td["passed"]=t.passed; td["interpretation"]=t.interpretation;
                py::dict det;
                for(auto& kv:t.details) det[kv.first.c_str()]=kv.second;
                td["details"]=det; tests.append(td);
            }
            d["tests"]=tests; return d;
        });

    m.def("nist_statistical_tests",&nist_statistical_tests,
          py::arg("bitstream_hex"),py::arg("num_bits")=0,
          "NIST SP 800-22 subset: Frequency, Block Frequency, Runs, Longest Run, Serial, Approximate Entropy");

    // ── Challenge ─────────────────────────────────────────────────────────────
    py::class_<CryptoChallenge>(m,"CryptoChallenge")
        .def_readonly("id",&CryptoChallenge::id)
        .def_readonly("algorithm",&CryptoChallenge::algorithm)
        .def_readonly("difficulty",&CryptoChallenge::difficulty)
        .def_readonly("category",&CryptoChallenge::category)
        .def_readonly("question",&CryptoChallenge::question)
        .def_readonly("hint",&CryptoChallenge::hint)
        .def_readonly("solution_approach",&CryptoChallenge::solution_approach)
        .def_readonly("plaintext_hex",&CryptoChallenge::plaintext_hex)
        .def_readonly("key_hex",&CryptoChallenge::key_hex)
        .def_readonly("ciphertext_hex",&CryptoChallenge::ciphertext_hex)
        .def_readonly("expected_answer",&CryptoChallenge::expected_answer)
        .def_readonly("points",&CryptoChallenge::points)
        .def_readonly("reference",&CryptoChallenge::reference)
        .def("to_dict",[](const CryptoChallenge& c){
            py::dict d;
            d["id"]=c.id; d["algorithm"]=c.algorithm; d["difficulty"]=c.difficulty;
            d["category"]=c.category; d["question"]=c.question; d["hint"]=c.hint;
            d["solution_approach"]=c.solution_approach; d["reference"]=c.reference;
            d["plaintext_hex"]=c.plaintext_hex; d["key_hex"]=c.key_hex;
            d["ciphertext_hex"]=c.ciphertext_hex;
            d["expected_answer"]=c.expected_answer; d["points"]=c.points;
            return d;
        });

    m.def("generate_challenge",&generate_challenge,
          py::arg("algorithm"),py::arg("difficulty")="easy",
          "Generate research-grade CTF challenge with solution approach and academic reference");
}
