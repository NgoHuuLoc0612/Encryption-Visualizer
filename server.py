"""
server.py  —  Research-Grade Encryption Visualizer
FastAPI backend: C++ engine (pybind11) + Python research analytics
"""
from __future__ import annotations
import sys, os, json, time, hashlib, secrets, math, base64
from pathlib import Path
from collections import Counter
from typing import Any, Optional, List
from datetime import datetime

BUILD_DIR = Path(__file__).parent / "build"
sys.path.insert(0, str(BUILD_DIR))
sys.path.insert(0, str(Path(__file__).parent))

try:
    import crypto_engine as _E
    NATIVE = True
    print("[OK] crypto_engine (C++ research-grade) loaded", flush=True)
except ImportError:
    NATIVE = False
    print("[WARN] crypto_engine not found — Python fallback active", flush=True)

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import uvicorn, asyncio

app = FastAPI(
    title="CryptoViz Research API",
    description="Research-grade cryptographic visualization and analysis engine",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/", response_class=HTMLResponse)
async def root():
    p = Path(__file__).parent / "index.html"
    return HTMLResponse(p.read_text("utf-8") if p.exists() else "<h1>index.html not found</h1>")

@app.get("/api/status")
async def status():
    return {
        "status": "online",
        "version": "3.0.0",
        "engine": "C++ research-grade via pybind11" if NATIVE else "Python fallback",
        "native_engine": NATIVE,
        "timestamp": datetime.utcnow().isoformat(),
        "algorithms": {
            "symmetric":   ["AES-128","AES-192","AES-256"],
            "modes":       ["ECB","CBC","CTR","GCM"],
            "stream":      ["ChaCha20","ChaCha20-Poly1305"],
            "hash":        ["SHA-256","SHA-3 (Keccak-256/512)","HMAC-SHA256","PBKDF2"],
            "asymmetric":  ["RSA","Diffie-Hellman"],
            "classical":   ["XOR","Vigenère"],
            "analysis":    ["Differential Cryptanalysis","Linear Approximation","SAC",
                           "Power Trace (CPA)","NIST SP 800-22 Tests","Kasiski","IoC"],
        }
    }

# ── Python analytics layer ────────────────────────────────────────────────────

def py_entropy(hex_data: str) -> dict:
    data = bytes.fromhex(hex_data) if hex_data else b""
    if not data: return {"entropy":0.0,"max_entropy":8.0,"efficiency":0.0,"byte_distribution":{}}
    c = Counter(data); n = len(data)
    e = -sum((v/n)*math.log2(v/n) for v in c.values())
    # Chi-squared vs uniform
    expected = n / 256
    chi2 = sum((cnt - expected)**2 / expected for cnt in c.values())
    chi2 += (256 - len(c)) * expected  # missing bytes
    return {
        "entropy": round(e, 6), "max_entropy": 8.0,
        "efficiency": round(e/8*100, 4),
        "chi_squared_uniform": round(chi2, 4),
        "byte_distribution": {k: v for k, v in sorted(c.items())},
        "unique_bytes": len(c),
    }

def py_frequency(text: str) -> dict:
    import string
    letters = [c.upper() for c in text if c.isalpha()]
    total = len(letters) or 1
    c = Counter(letters)
    en = {"E":12.7,"T":9.1,"A":8.2,"O":7.5,"I":7.0,"N":6.7,"S":6.3,"H":6.1,"R":6.0,
          "D":4.3,"L":4.0,"C":2.8,"U":2.8,"M":2.4,"W":2.4,"F":2.2,"G":2.0,"Y":2.0,
          "P":1.9,"B":1.5,"V":1.0,"K":0.8,"J":0.2,"X":0.2,"Q":0.1,"Z":0.1}
    chi2 = sum((c.get(ch,0)/total*100-en.get(ch,0))**2/max(en.get(ch,0.01),0.01)
               for ch in string.ascii_uppercase)
    # Coincidence index
    ci = sum(c.get(ch,0)*(c.get(ch,0)-1) for ch in string.ascii_uppercase)
    ci = ci / (total*(total-1)) if total > 1 else 0
    return {
        "frequencies": {ch: round(c.get(ch,0)/total*100, 4) for ch in string.ascii_uppercase},
        "chi_squared": round(chi2, 4),
        "index_of_coincidence": round(ci, 6),
        "is_likely_english": chi2 < 50,
        "english_ic": 0.0667,
        "total_letters": total,
    }

def py_ioc(ct: str) -> dict:
    letters = [c.upper() for c in ct if c.isalpha()]
    n = len(letters)
    if n < 2: return {"ioc":0.0,"estimated_key_length":1,"key_length_iocs":{}}
    c = Counter(letters)
    ioc_val = sum(v*(v-1) for v in c.values()) / (n*(n-1))
    kiocs = {}
    for kl in range(1, min(21, n)):
        groups = ["".join(letters[i::kl]) for i in range(kl)]
        gis = []
        for g in groups:
            gc = Counter(g); gn = len(g)
            if gn > 1: gis.append(sum(v*(v-1) for v in gc.values())/(gn*(gn-1)))
        if gis: kiocs[kl] = round(sum(gis)/len(gis), 6)
    best = max(kiocs, key=lambda k: kiocs[k]) if kiocs else 1
    return {
        "ioc": round(ioc_val, 6), "english_ioc": 0.0667, "random_ioc": 0.0385,
        "key_length_iocs": kiocs, "estimated_key_length": best,
        "kasiski_note": "Combined Kasiski + IoC estimation"
    }

def py_avalanche(r_a: dict, r_b: dict) -> dict:
    a = bytes.fromhex(r_a["ciphertext_hex"]); b = bytes.fromhex(r_b["ciphertext_hex"])
    diffs = sum(bin(x^y).count("1") for x,y in zip(a,b))
    per_byte = [bin(x^y).count("1") for x,y in zip(a,b)]
    return {
        "bits_flipped": diffs, "total_bits": 128,
        "avalanche_percent": round(diffs/128*100, 4),
        "per_byte": per_byte,
        "sac_compliant": 45 <= diffs/128*100 <= 55,
        "interpretation": "Meets SAC (≈50%)" if 45 <= diffs/128*100 <= 55 else
                          ("Under-diffused" if diffs/128*100 < 45 else "Over-diffused"),
    }

# ── Request models ─────────────────────────────────────────────────────────────
class AESReq(BaseModel):
    plaintext_hex: str = Field(..., min_length=2)
    key_hex: str = Field(..., min_length=32)
    mode: str = "ECB"
    iv_hex: str = ""

class ChaChaReq(BaseModel):
    plaintext_hex: str
    key_hex: str = Field(..., min_length=64, max_length=64)
    nonce_hex: str = Field(..., min_length=24, max_length=24)
    counter: int = 0
    with_poly1305: bool = False
    aad_hex: str = ""

class SHA256Req(BaseModel): message_hex: str
class SHA3Req(BaseModel):
    message_hex: str
    variant: str = "SHA3-256"

class HMACReq(BaseModel): key_hex: str; msg_hex: str

class PBKDF2Req(BaseModel):
    password_hex: str; salt_hex: str
    iterations: int = Field(10000, ge=1, le=1000000)
    dklen: int = Field(32, ge=1, le=64)

class RSAReq(BaseModel):
    p: int = Field(..., ge=3); q: int = Field(..., ge=3)
    e: int = Field(17, ge=3); msg_hex: str

class DHReq(BaseModel):
    p: int = 23; g: int = 5; alice_priv: int = 6; bob_priv: int = 15

class XORReq(BaseModel): plaintext_hex: str; key_hex: str
class VigenereReq(BaseModel): plaintext: str; key: str; encrypt: bool = True

class DiffReq(BaseModel):
    pt1_hex: str = Field(..., min_length=32, max_length=32)
    pt2_hex: str = Field(..., min_length=32, max_length=32)
    key_hex: str = Field(..., min_length=32)
    num_rounds: int = Field(4, ge=1, le=14)

class LinApproxReq(BaseModel):
    input_mask_hex: str; output_mask_hex: str
    num_rounds: int = Field(3, ge=1, le=10)

class SACReq(BaseModel):
    key_hex: str = Field(..., min_length=32)
    num_samples: int = Field(256, ge=64, le=2000)

class PowerTraceReq(BaseModel):
    pt_hex: str = Field(..., min_length=32, max_length=32)
    key_hex: str = Field(..., min_length=32, max_length=32)
    noise_sigma: float = Field(0.1, ge=0.0, le=2.0)

class NISTReq(BaseModel):
    bitstream_hex: str = Field(..., min_length=32)
    num_bits: int = 0

class AvalancheReq(BaseModel):
    plaintext_hex: str; key_hex: str; flip_bit_position: int = 0

class EntropyReq(BaseModel): data_hex: str
class FreqReq(BaseModel): text: str
class IoCReq(BaseModel): ciphertext: str
class ChallengeReq(BaseModel):
    algorithm: str = "AES"
    difficulty: str = "easy"

# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.post("/api/aes/encrypt")
async def aes_encrypt(req: AESReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.aes_encrypt_visualize(req.plaintext_hex, req.key_hex, req.mode, req.iv_hex)
            data = r.to_dict()
        else:
            from Crypto.Cipher import AES
            key = bytes.fromhex(req.key_hex); pt = bytes.fromhex(req.plaintext_hex)
            pad = 16 - len(pt)%16; pt += bytes([pad]*pad)
            cipher = AES.new(key, AES.MODE_ECB)
            data = {"algorithm":f"AES-{len(key)*8}","mode":"ECB",
                    "ciphertext_hex":cipher.encrypt(pt).hex(),
                    "rounds":[],"key_schedule":[],"sbox_hex":[],
                    "round_avalanche":[],"hw_trace":[],"strict_avalanche":0.0,"num_active_sboxes":0}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        data["entropy"] = py_entropy(data.get("ciphertext_hex",""))
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/chacha20/encrypt")
async def chacha20_encrypt(req: ChaChaReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.chacha20_encrypt_visualize(req.plaintext_hex, req.key_hex, req.nonce_hex,
                                               req.counter, req.with_poly1305, req.aad_hex)
            data = r.to_dict()
        else: data = {"algorithm":"ChaCha20","ciphertext_hex":"","rounds":[],"keystream_hex":"","initial_state":[],"final_keystream_state":[],"has_poly1305":False}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        data["entropy"] = py_entropy(data.get("ciphertext_hex",""))
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/sha256/hash")
async def sha256_hash(req: SHA256Req):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.sha256_visualize(req.message_hex); data = r.to_dict()
        else:
            dig = hashlib.sha256(bytes.fromhex(req.message_hex)).hexdigest()
            data = {"algorithm":"SHA-256","digest_hex":dig,"blocks":[],"initial_hash":[],
                    "padded_message_hex":"","num_blocks":0,"compression_avalanche":0.0,"length_extension_demo":""}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/sha3/hash")
async def sha3_hash(req: SHA3Req):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.sha3_visualize(req.message_hex, req.variant); data = r.to_dict()
        else:
            import hashlib
            alg = {"SHA3-256":hashlib.sha3_256,"SHA3-512":hashlib.sha3_512}.get(req.variant,hashlib.sha3_256)
            data = {"algorithm":req.variant,"digest_hex":alg(bytes.fromhex(req.message_hex)).hexdigest(),
                    "rounds":[],"absorption_states":[],"squeezing_states":[],"rate_bits":1088,"capacity_bits":512}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/hmac/compute")
async def hmac_compute(req: HMACReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.hmac_sha256_visualize(req.key_hex, req.msg_hex); data = r.to_dict()
        else:
            import hmac
            mac = hmac.new(bytes.fromhex(req.key_hex), bytes.fromhex(req.msg_hex), hashlib.sha256).hexdigest()
            data = {"algorithm":"HMAC-SHA256","mac_hex":mac,"ipad_key_hex":"","opad_key_hex":"",
                    "inner_hash_hex":"","outer_hash_hex":""}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/pbkdf2/derive")
async def pbkdf2_derive(req: PBKDF2Req):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.pbkdf2_visualize(req.password_hex, req.salt_hex, req.iterations, req.dklen)
            data = r.to_dict()
        else:
            import hashlib
            dk = hashlib.pbkdf2_hmac("sha256",bytes.fromhex(req.password_hex),bytes.fromhex(req.salt_hex),req.iterations,req.dklen)
            data = {"algorithm":"PBKDF2-HMAC-SHA256","derived_key_hex":dk.hex(),"rounds":[],"entropy_bits":0,"estimated_crack_time_ms":0}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/rsa/encrypt")
async def rsa_encrypt(req: RSAReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.rsa_visualize(req.p, req.q, req.e, req.msg_hex); data = r.to_dict()
        else: data = {"algorithm":"RSA","operations":[],"p":req.p,"q":req.q,"n":req.p*req.q,"phi_n":(req.p-1)*(req.q-1),"e":req.e,"d":0,"security_bits":0,"wiener_attack_result":"unknown","timing_side_channel":[]}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/dh/exchange")
async def dh_exchange(req: DHReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.dh_visualize(req.p, req.g, req.alice_priv, req.bob_priv); data = r.to_dict()
        else: data = {"algorithm":"DiffieHellman","prime":req.p,"generator":req.g,"alice_private":req.alice_priv,"alice_public":0,"bob_private":req.bob_priv,"bob_public":0,"alice_shared":0,"bob_shared":0,"dlog_steps":[],"small_subgroup_vulnerable":False,"pohlig_hellman_structure":"","security_bits":0}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/xor/encrypt")
async def xor_encrypt(req: XORReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.xor_visualize(req.plaintext_hex, req.key_hex); data = r.to_dict()
        else:
            pt = bytes.fromhex(req.plaintext_hex); key = bytes.fromhex(req.key_hex)
            ct = bytes(pt[i]^key[i%len(key)] for i in range(len(pt)))
            data = {"algorithm":"XOR","ciphertext_hex":ct.hex(),"steps":[],"key_entropy":0.0,"ic":0.0}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/vigenere/encrypt")
async def vigenere_encrypt(req: VigenereReq):
    t = time.perf_counter()
    try:
        if NATIVE:
            r = _E.vigenere_visualize(req.plaintext, req.key, req.encrypt); data = r.to_dict()
        else: data = {"algorithm":"Vigenere","plaintext":req.plaintext,"key":req.key,"ciphertext":"","steps":[],"kasiski_key_length_estimate":0,"ioc_by_keylength":[],"recovered_key_bytes":[]}
        data["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        data["frequency"] = py_frequency(data.get("ciphertext", req.plaintext))
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

# ── Research Analysis Endpoints ────────────────────────────────────────────────

@app.post("/api/analysis/differential")
async def differential(req: DiffReq):
    if not NATIVE: raise HTTPException(503, "C++ engine required")
    try:
        r = _E.aes_differential_trail(req.pt1_hex, req.pt2_hex, req.key_hex, req.num_rounds)
        return JSONResponse(r.to_dict())
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/linear")
async def linear(req: LinApproxReq):
    if not NATIVE: raise HTTPException(503, "C++ engine required")
    try:
        r = _E.aes_linear_approximation(req.input_mask_hex, req.output_mask_hex, req.num_rounds)
        return JSONResponse(r.to_dict())
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/sac")
async def sac(req: SACReq):
    if not NATIVE: raise HTTPException(503, "C++ engine required")
    try:
        r = _E.aes_strict_avalanche(req.key_hex, req.num_samples)
        data = r.to_dict()
        # Flatten bit_matrix to per-bit averages for frontend (128×128 is large)
        data["per_bit_avalanche"] = r.per_bit_avalanche
        data.pop("bit_matrix", None)  # too large for typical response
        return JSONResponse(data)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/power_trace")
async def power_trace(req: PowerTraceReq):
    if not NATIVE: raise HTTPException(503, "C++ engine required")
    try:
        r = _E.aes_power_trace(req.pt_hex, req.key_hex, req.noise_sigma)
        return JSONResponse(r.to_dict())
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/nist")
async def nist_tests(req: NISTReq):
    try:
        if NATIVE:
            r = _E.nist_statistical_tests(req.bitstream_hex, req.num_bits)
            return JSONResponse(r.to_dict())
        else:
            return JSONResponse({"error":"C++ engine required for NIST tests","passed_count":0,"total_count":0,"overall_score":0,"is_random":False,"tests":[]})
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/avalanche")
async def avalanche_endpoint(req: AvalancheReq):
    t = time.perf_counter()
    if not NATIVE: raise HTTPException(503, "C++ engine required")
    try:
        ra = _E.aes_encrypt_visualize(req.plaintext_hex, req.key_hex).to_dict()
        pt = bytearray(bytes.fromhex(req.plaintext_hex))
        pt[req.flip_bit_position//8] ^= (1 << (7 - req.flip_bit_position%8))
        rb = _E.aes_encrypt_visualize(pt.hex(), req.key_hex).to_dict()
        av = py_avalanche(ra, rb)
        av["elapsed_ms"] = round((time.perf_counter()-t)*1000, 3)
        av["original_ct"] = ra["ciphertext_hex"]; av["modified_ct"] = rb["ciphertext_hex"]
        av["flipped_bit"] = req.flip_bit_position
        av["round_avalanche"] = ra.get("round_avalanche",[])
        return JSONResponse(av)
    except Exception as ex: raise HTTPException(400, str(ex))

@app.post("/api/analysis/entropy")
async def entropy_endpoint(req: EntropyReq):
    return JSONResponse(py_entropy(req.data_hex))

@app.post("/api/analysis/frequency")
async def frequency_endpoint(req: FreqReq):
    return JSONResponse(py_frequency(req.text))

@app.post("/api/analysis/ioc")
async def ioc_endpoint(req: IoCReq):
    return JSONResponse(py_ioc(req.ciphertext))

@app.post("/api/challenge/generate")
async def gen_challenge(req: ChallengeReq):
    try:
        if NATIVE:
            ch = _E.generate_challenge(req.algorithm, req.difficulty)
            return JSONResponse(ch.to_dict())
        return JSONResponse({
            "id": secrets.token_hex(8), "algorithm": req.algorithm,
            "difficulty": req.difficulty, "category": "unknown",
            "question": "Build the C++ extension to enable challenge generation.",
            "hint": "Run: python build.py", "solution_approach": "",
            "reference": "", "plaintext_hex": "", "key_hex": "",
            "ciphertext_hex": "", "expected_answer": "", "points": 0,
        })
    except Exception as ex: raise HTTPException(400, str(ex))

@app.get("/api/aes/stream")
async def aes_stream(plaintext_hex: str, key_hex: str, mode: str = "ECB"):
    async def gen():
        try:
            if not NATIVE:
                yield f"data: {json.dumps({'error':'C++ engine required'})}\n\n"; return
            r = _E.aes_encrypt_visualize(plaintext_hex, key_hex, mode)
            data = r.to_dict()
            meta = {"type":"meta","algorithm":data["algorithm"],"mode":data["mode"],
                    "num_rounds":len(data["rounds"]),"strict_avalanche":data.get("strict_avalanche",0)}
            yield f"data: {json.dumps(meta)}\n\n"
            for rd in data["rounds"]:
                yield f"data: {json.dumps({'type':'round','payload':rd})}\n\n"
                await asyncio.sleep(0.06)
            yield f"data: {json.dumps({'type':'done','ciphertext':data['ciphertext_hex'],'hw_trace':data.get('hw_trace',[]),'round_avalanche':data.get('round_avalanche',[])})}\n\n"
        except Exception as ex:
            yield f"data: {json.dumps({'error':str(ex)})}\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no"})

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
