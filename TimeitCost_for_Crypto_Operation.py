import hashlib
import os
import timeit
import secrets
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import HMAC
import pandas as pd  # Import pandas
import psutil
import platform
from ecpy.curves import Curve
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

ITERATION = 10

class ECC160:
    def __init__(self, p, a, b, Gx, Gy, n):
        self.p = p
        self.a = a
        self.b = b
        self.Gx = Gx
        self.Gy = Gy
        self.n = n

    def point_add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        if P == Q:
            return self.point_double(P)
        if P[0] == Q[0]:
            return None
        slope = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.p) % self.p
        Rx = (slope**2 - P[0] - Q[0]) % self.p
        Ry = (slope * (P[0] - Rx) - P[1]) % self.p
        return (Rx, Ry)

    def point_double(self, P):
        if P is None:
            return None
        slope = (3 * P[0]**2 + self.a) * pow(2 * P[1], -1, self.p) % self.p
        Rx = (slope**2 - 2 * P[0]) % self.p
        Ry = (slope * (P[0] - Rx) - P[1]) % self.p
        return (Rx, Ry)

    def point_multiply(self, k, P):
        if k == 0 or P is None:
            return None
        R = P
        result = None
        while k > 0:
            if k & 1:
                result = self.point_add(result, R)
            R = self.point_double(R)
            k >>= 1
        return result

    def generate_keypair(self):
        private_key = secrets.randbelow(self.n)
        public_key = self.point_multiply(private_key, (self.Gx, self.Gy))
        return private_key, public_key

    def ecdh(self, private_key, public_key_other):
        shared_secret = self.point_multiply(private_key, public_key_other)
        return shared_secret

    def ecdsa_sign(self, private_key, message):
        z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.n
        while True:
            k = secrets.randbelow(self.n)
            R = self.point_multiply(k, (self.Gx, self.Gy))
            r = R[0] % self.n
            if r == 0:
                continue
            s = (pow(k, -1, self.n) * (z + r * private_key)) % self.n
            if s == 0:
                continue
            return r, s

    def ecdsa_verify(self, public_key, message, signature):
        if signature is None:
            return False
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False
        z = int(hashlib.sha256(message.encode()).hexdigest(), 16) % self.n
        w = pow(s, -1, self.n)
        u1 = (z * w) % self.n
        u2 = (r * w) % self.n
        P1 = self.point_multiply(u1, (self.Gx, self.Gy))
        P2 = self.point_multiply(u2, public_key)
        R = self.point_add(P1, P2)
        if R is None:
            return False
        v = R[0] % self.n
        return v == r

    def encrypt(self, message, public_key_recipient):
        k = secrets.randbelow(self.n)
        C1 = self.point_multiply(k, (self.Gx, self.Gy))
        S = self.point_multiply(k, public_key_recipient)
        if S is None:
            raise ValueError("Invalid public key. Shared secret point is None")
        shared_secret = str(S[0]) + str(S[1])
        hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
        ciphertext = b""
        for i in range(len(message)):
            ciphertext += bytes([message[i] ^ hashed_secret[i % len(hashed_secret)]])
        return C1, ciphertext

    def decrypt(self, ciphertext, private_key, C1):
        S = self.point_multiply(private_key, C1)
        if S is None:
            raise ValueError("Invalid private key or ciphertext. Shared secret point is None")
        shared_secret = str(S[0]) + str(S[1])
        hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
        plaintext = b""
        for i in range(len(ciphertext)):
            plaintext += bytes([ciphertext[i] ^ hashed_secret[i % len(hashed_secret)]])
        return plaintext

def hash_sha256(data):
    """Hashes data using SHA256 and measures time with timeit.timeit."""
    def hash_wrapper():
        hashlib.sha256(data).hexdigest()

    elapsed_time = timeit.timeit(hash_wrapper, number=ITERATION) / ITERATION
    return hashlib.sha256(data).hexdigest(), elapsed_time

def hash_sha512(data):
    """Hashes data using SHA512 and measures time with timeit.timeit."""
    def hash_wrapper():
        hashlib.sha512(data).hexdigest()

    elapsed_time = timeit.timeit(hash_wrapper, number=ITERATION) / ITERATION
    return hashlib.sha512(data).hexdigest(), elapsed_time

def time_hash_function(func, data, repetitions=ITERATION):
    """Time a hash function with given data"""
    wrapper = lambda: func(data)
    return timeit.timeit(wrapper, number=repetitions) / repetitions

def rsa_sign_verify(key, message):
    """Signs and verifies a message using RSA and measures time with timeit.timeit."""
    def sign_wrapper():
        pkcs1_15.new(key).sign(SHA256.new(message))

    def verify_wrapper(signature):
        pkcs1_15.new(key).verify(SHA256.new(message), signature)

    signature = pkcs1_15.new(key).sign(SHA256.new(message)) #get signature first
    elapsed_time_sign = timeit.timeit(sign_wrapper, number=ITERATION) / ITERATION
    elapsed_time_verify = timeit.timeit(lambda: verify_wrapper(signature), number=ITERATION) / ITERATION

    return elapsed_time_sign, elapsed_time_verify

def ecc_key_generation(ecc):
    """Generates an ECC key pair and measures time with timeit.timeit."""
    def keygen_wrapper():
        ecc.generate_keypair()

    elapsed_time = timeit.timeit(keygen_wrapper, number=ITERATION) / ITERATION
    ecc.generate_keypair() # generate keys once to ensure correct operation.
    return elapsed_time

def ecc_point_multiplication(ecc, k, P):
    """Performs ECC point multiplication and measures time with timeit.timeit."""
    def point_mult_wrapper():
        ecc.point_multiply(k, P)

    elapsed_time = timeit.timeit(point_mult_wrapper, number=ITERATION) / ITERATION
    ecc.point_multiply(k, P) # perform point multiplication once.
    return elapsed_time

def hmac_time(key, message):
    """Computes HMAC and measures time with timeit.timeit."""
    def hmac_wrapper():
        h = HMAC.new(key, msg=message, digestmod=SHA256)
        h.digest()

    elapsed_time = timeit.timeit(hmac_wrapper, number=ITERATION) / ITERATION
    HMAC.new(key, msg=message, digestmod=SHA256).digest() #run hmac once
    return elapsed_time

def ecc_encrypt_decrypt_time(ecc, message, key=160):
    if key == 160:
        private_key_recipient, public_key_recipient = ecc.generate_keypair()

        def encrypt_wrapper():
            return ecc.encrypt(message, public_key_recipient)

        def decrypt_wrapper(C1, ciphertext):
            ecc.decrypt(ciphertext, private_key_recipient, C1)

        encryption_time_160 = timeit.timeit(encrypt_wrapper, number=ITERATION) / ITERATION
        C1, ciphertext = encrypt_wrapper()

        decryption_time_160 = timeit.timeit(lambda: decrypt_wrapper(C1, ciphertext), number=ITERATION) / ITERATION

        ciphertext_size_160 = len(ciphertext)

        return encryption_time_160, decryption_time_160, ciphertext_size_160
    elif key == 192:
        curve = Curve.get_curve("secp192r1")
        private_key = secrets.randbelow(curve.order)
        public_key = private_key * curve.generator

        def encrypt_wrapper():
            k = secrets.randbelow(curve.order)
            C1 = k * curve.generator
            S = k * public_key
            shared_secret = str(S.x) + str(S.y)
            hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
            ciphertext = b""
            for i in range(len(message)):
                ciphertext += bytes([message[i] ^ hashed_secret[i % len(hashed_secret)]])
            return C1, ciphertext

        def decrypt_wrapper(C1, ciphertext):
            S = private_key * C1
            shared_secret = str(S.x) + str(S.y)
            hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
            plaintext = b""
            for i in range(len(ciphertext)):
                plaintext += bytes([ciphertext[i] ^ hashed_secret[i % len(hashed_secret)]])
            return plaintext

        encryption_time_192 = timeit.timeit(encrypt_wrapper, number=ITERATION) / ITERATION
        C1, ciphertext = encrypt_wrapper()

        decryption_time_192 = timeit.timeit(lambda: decrypt_wrapper(C1, ciphertext), number=ITERATION) / ITERATION

        ciphertext_size_192 = len(ciphertext)
        return encryption_time_192, decryption_time_192, ciphertext_size_192
    elif key == 256:
        curve = Curve.get_curve("secp256r1")
        private_key = secrets.randbelow(curve.order)
        public_key = private_key * curve.generator

        def encrypt_wrapper():
            k = secrets.randbelow(curve.order)
            C1 = k * curve.generator
            S = k * public_key
            shared_secret = str(S.x) + str(S.y)
            hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
            ciphertext = b""
            for i in range(len(message)):
                ciphertext += bytes([message[i] ^ hashed_secret[i % len(hashed_secret)]])
            return C1, ciphertext

        def decrypt_wrapper(C1, ciphertext):
            S = private_key * C1
            shared_secret = str(S.x) + str(S.y)
            hashed_secret = hashlib.sha256(shared_secret.encode()).digest()
            plaintext = b""
            for i in range(len(ciphertext)):
                plaintext += bytes([ciphertext[i] ^ hashed_secret[i % len(hashed_secret)]])
            return plaintext

        encryption_time_256 = timeit.timeit(encrypt_wrapper, number=ITERATION) / ITERATION
        C1, ciphertext = encrypt_wrapper()

        decryption_time_256 = timeit.timeit(lambda: decrypt_wrapper(C1, ciphertext), number=ITERATION) / ITERATION

        ciphertext_size_256 = len(ciphertext)
        return encryption_time_256, decryption_time_256, ciphertext_size_256
    else:
        raise ValueError("Unsupported key size")

def rsa_encrypt_decrypt_time(key, message):
    """Measures RSA encryption and decryption time using timeit.timeit, handles larger data."""

    # Split message if it's too large for direct RSA encryption
    max_plaintext_len = key.size_in_bytes() - 2 * SHA256.digest_size - 2  # OAEP padding limits

    if len(message) > max_plaintext_len:
        print(f"Warning: Message size ({len(message)*8} bits) exceeds maximum RSA plaintext length ({max_plaintext_len*8} bits) for key size {key.size_in_bits()} bits. Splitting into chunks.")
        chunks = [message[i:i + max_plaintext_len] for i in range(0, len(message), max_plaintext_len)]

        def encrypt_wrapper():
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            ciphertexts = [cipher.encrypt(chunk) for chunk in chunks]
            return b''.join(ciphertexts)

        def decrypt_wrapper(ciphertext):
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            chunk_size = key.size_in_bytes()
            decrypted_chunks = [cipher.decrypt(ciphertext[i:i + chunk_size]) for i in range(0, len(ciphertext), chunk_size)]
            b''.join(decrypted_chunks)

    else:
        def encrypt_wrapper():
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            return cipher.encrypt(message)

        def decrypt_wrapper(ciphertext):
            cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
            cipher.decrypt(ciphertext)

    ciphertext = encrypt_wrapper()  # Obtain ciphertext once

    encrypt_time = timeit.timeit(encrypt_wrapper, number=ITERATION) / ITERATION
    decrypt_time = timeit.timeit(lambda: decrypt_wrapper(ciphertext), number=ITERATION) / ITERATION

    return encrypt_time, decrypt_time

def aes_encrypt_decrypt_time(key_size, data):
    """Measures AES encryption and decryption time for given key size"""
    # Generate random key and IV
    key = secrets.token_bytes(key_size // 8)
    iv = secrets.token_bytes(16)  # AES block size is 16 bytes
    
    # Pad the data if needed
    padded_data = pad(data, AES.block_size)
    
    def encrypt_wrapper():
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded_data)
    
    def decrypt_wrapper(ciphertext):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Run encryption and measure time
    encrypt_time = timeit.timeit(encrypt_wrapper, number=ITERATION) / ITERATION
    ciphertext = encrypt_wrapper()
    ciphertext_size_bits = len(ciphertext) * 8 
    
    # Run decryption and measure time
    decrypt_time = timeit.timeit(lambda: decrypt_wrapper(ciphertext), number=ITERATION) / ITERATION
    
    return encrypt_time, decrypt_time, ciphertext_size_bits

# def xor_time(data):
#     """Measures XOR operation time with itself (acts as identity function)"""
#     def xor_wrapper():
#         return bytes([b ^ 0x55 for b in data])  # XOR with fixed pattern (0x55)
    
#     elapsed_time = timeit.timeit(xor_wrapper, number=ITERATION) / ITERATION
#     return elapsed_time, len(data) * 8  # Output size same as input

def xor_time(data):
    pattern = 0x55
    # Pre-convert pattern to bytes to avoid per-byte conversion
    pattern_bytes = bytes([pattern] * len(data))
    
    def xor_wrapper():
        return bytes(a ^ b for a, b in zip(data, pattern_bytes))
    
    # Warm-up (avoid first-run penalties)
    xor_wrapper()
    
    elapsed = timeit.timeit(xor_wrapper, number=ITERATION) / ITERATION
    return elapsed, len(data) * 8

def get_cpu_details():
    """Cross-platform system information collection"""
    cpu_details = []
    process = psutil.Process()
    
    try:
        # ===== Core System Info =====
        cpu_details.extend([
            ["System", platform.system()],
            ["OS Version", f"{platform.release()} ({platform.version()})"],
            ["Hostname", platform.node()],
            ["Architecture", platform.machine()],
        ])

        # ===== CPU Details =====
        cpu_brand = platform.processor()
        try:
            if platform.system() == "Windows":
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                   r"HARDWARE\DESCRIPTION\System\CentralProcessor\0") as key:
                    cpu_brand = winreg.QueryValueEx(key, "ProcessorNameString")[0].strip()
            elif platform.system() == "Linux":
                with open('/proc/cpuinfo') as f:
                    for line in f:
                        if line.strip() and line.split(':')[0].strip() == 'model name':
                            cpu_brand = line.split(':')[1].strip()
                            break
        except Exception:
            pass

        cpu_freq = psutil.cpu_freq()
        cpu_stats = psutil.cpu_stats()
        
        cpu_details.extend([
            ["Processor", cpu_brand],
            ["Physical Cores", psutil.cpu_count(logical=False)],
            ["Logical Cores", psutil.cpu_count(logical=True)],
            ["Current Frequency (MHz)", round(cpu_freq.current, 2) if cpu_freq else "N/A"],
            ["Max Frequency (MHz)", round(cpu_freq.max, 2) if cpu_freq else "N/A"],
            ["Context Switches", cpu_stats.ctx_switches],
            ["Interrupts", cpu_stats.interrupts],
        ])

        # ===== Memory Info ===== 
        mem = psutil.virtual_memory()
        swap = psutil.swap_memory()
        
        memory_info = [
            ["Total RAM (GB)", round(mem.total / (1024**3), 2)],
            ["Available RAM (GB)", round(mem.available / (1024**3), 2)],
            ["RAM Usage (%)", mem.percent],
            ["Swap Total (GB)", round(swap.total / (1024**3), 2)],
            ["Swap Used (GB)", round(swap.used / (1024**3), 2)],
        ]
        
        # Add platform-specific memory attributes
        if hasattr(mem, 'cached'):
            memory_info.append(["Cached RAM (GB)", round(mem.cached / (1024**3), 2)])
        if hasattr(mem, 'buffers'):
            memory_info.append(["Buffers (GB)", round(mem.buffers / (1024**3), 2)])
        
        cpu_details.extend(memory_info)

        # ===== Process-Specific Metrics =====
        cpu_details.extend([
            ["Process Threads", process.num_threads()],
            ["Process Memory (MB)", round(process.memory_info().rss/(1024**2), 2)],
            ["Process CPU%", process.cpu_percent()],
        ])

        # ===== Optional Sensors =====
        try:
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps and 'coretemp' in temps:
                    cpu_details.append(["CPU Temp (°C)", temps['coretemp'][0].current])
        except:
            pass

    except Exception as e:
        cpu_details.append(["Collection Error", str(e)])

    return cpu_details

def generate_data(size_bits):
    size_bytes = size_bits // 8
    return os.urandom(size_bytes)

p = 2**160 - 2**31 - 1
a = 0
b = 7
Gx = 0x4a96b5688f59a958c829af5bfc858619789c628f
Gy = 0x63133988ba947761b72608bc824744696b9f166b
n = 0xffffffffffffffffffffffff99def836146bc9b1b4d22831

ecc = ECC160(p, a, b, Gx, Gy, n)

data_sizes = [32,64, 128, 192, 256, 512, 1024]  # Test different plaintext sizes

# Get CPU info
cpu_info = get_cpu_details()
cpu_df = pd.DataFrame(cpu_info, columns=["Hardware", "Info"])

print(cpu_df)
results = []
for size_bits in data_sizes:
    data = generate_data(size_bits)
    sha_256_time = time_hash_function(hash_sha256, data)
    sha_512_time = time_hash_function(hash_sha512, data)
    # rsa_1024_sign, rsa_1024_verify = rsa_sign_verify(RSA.generate(1024), data)
    # rsa_2048_sign, rsa_2048_verify = rsa_sign_verify(RSA.generate(2048), data)
    rsa_1024_encrypt, rsa_1024_decrypt = rsa_encrypt_decrypt_time(RSA.generate(1024), data)
    rsa_2048_encrypt, rsa_2048_decrypt = rsa_encrypt_decrypt_time(RSA.generate(2048), data)
    # ecc_mult_time = ecc_point_multiplication(ecc, secrets.randbelow(n), (Gx, Gy))
    ecc_enc_time_160, ecc_dec_time_160, ciphertext_size_160 = ecc_encrypt_decrypt_time(ecc, data, key=160)
    ecc_enc_time_192, ecc_dec_time_192, ciphertext_size_192 = ecc_encrypt_decrypt_time(ecc=None,message=data, key=192)
    ecc_enc_time_256, ecc_dec_time_256, ciphertext_size_256 = ecc_encrypt_decrypt_time(ecc=None,message=data, key=256)
    # hmac_t = hmac_time(secrets.token_bytes(32), data)

    aes128_encrypt, aes128_decrypt, aes128_size = aes_encrypt_decrypt_time(128, data)
    aes192_encrypt, aes192_decrypt, aes192_size = aes_encrypt_decrypt_time(192, data)
    aes256_encrypt, aes256_decrypt, aes256_size = aes_encrypt_decrypt_time(256, data)

    xor_time_encrypt, xor_size = xor_time(data)
    

    results.append({
        "Data Size": size_bits,
        "XOR Time": xor_time_encrypt,
        "XOR Output Size": xor_size,
        "SHA-256 Time": sha_256_time,
        "SHA-512 Time": sha_512_time,
        # "SHA-256 Output Size": 256,  # SHA-256 always outputs 256 bits
        # "SHA-512 Output Size": 512,  # SHA-512 always outputs 512 bits
        # "RSA 1024 Sign": rsa_1024_sign,
        # "RSA 1024 Verify": rsa_1024_verify,
        # "RSA 2048 Sign": rsa_2048_sign,
        # "RSA 2048 Verify": rsa_2048_verify,
        # "ECC Point Mult": ecc_mult_time,
        "ECC-160 Encrypt": ecc_enc_time_160,
        "ECC-160 Decrypt": ecc_dec_time_160,
        "ECC-160 Cipher Size": ciphertext_size_160*8,
        "ECC-192 Encrypt": ecc_enc_time_192,
        "ECC-192 Decrypt": ecc_dec_time_192,
        "ECC-192 Cipher Size": ciphertext_size_192*8,
        "ECC-256 Encrypt": ecc_enc_time_256,
        "ECC-256 Decrypt": ecc_dec_time_256,
        "ECC-256 Cipher Size": ciphertext_size_256*8,
        # "HMAC Time": hmac_t,
        "RSA 1024 Encrypt": rsa_1024_encrypt,
        "RSA 1024 Decrypt": rsa_1024_decrypt,
        "RSA 1024 Cipher Size": 1024,  # RSA-1024 output is always 1024 bits
        "RSA 2048 Encrypt": rsa_2048_encrypt,
        "RSA 2048 Decrypt": rsa_2048_decrypt,
        "RSA 2048 Cipher Size": 2048,  # RSA-2048 output is always 2048 bits
        "AES-128 Encrypt": aes128_encrypt,
        "AES-128 Decrypt": aes128_decrypt,
        "AES-128 Cipher Size": aes128_size,
        "AES-192 Encrypt": aes192_encrypt,
        "AES-192 Decrypt": aes192_decrypt,
        "AES-192 Cipher Size": aes192_size,
        "AES-256 Encrypt": aes256_encrypt,
        "AES-256 Decrypt": aes256_decrypt,
        "AES-256 Cipher Size": aes256_size,
    })

# Transform results to have algorithms as rows and data sizes as columns
operations = [
    ("XOR", "Time", "XOR Time"),
    ("XOR", "Output Size", "XOR Output Size"),
    ("SHA-256", "Hashing", "SHA-256 Time"),
    # ("SHA-256", "Output Size", "SHA-256 Output Size"),
    ("SHA-512", "Hashing", "SHA-512 Time"),
    # ("SHA-512", "Output Size", "SHA-512 Output Size"),
    ("ECC-160", "Encrypt", "ECC-160 Encrypt"),
    ("ECC-160", "Decrypt", "ECC-160 Decrypt"),
    ("ECC-160", "Cipher Size", "ECC-160 Cipher Size"),
    ("ECC-192", "Encrypt", "ECC-192 Encrypt"),
    ("ECC-192", "Decrypt", "ECC-192 Decrypt"),
    ("ECC-192", "Cipher Size", "ECC-192 Cipher Size"),
    ("ECC-256", "Encrypt", "ECC-256 Encrypt"),
    ("ECC-256", "Decrypt", "ECC-256 Decrypt"),
    ("ECC-256", "Cipher Size", "ECC-256 Cipher Size"),
    ("RSA-1024", "Encrypt", "RSA 1024 Encrypt"),
    ("RSA-1024", "Decrypt", "RSA 1024 Decrypt"),
    ("RSA-1024", "Cipher Size", "RSA 1024 Cipher Size"),
    ("RSA-2048", "Encrypt", "RSA 2048 Encrypt"),
    ("RSA-2048", "Decrypt", "RSA 2048 Decrypt"),
    ("RSA-2048", "Cipher Size", "RSA 2048 Cipher Size"),
    ("AES-128", "Encrypt", "AES-128 Encrypt"),
    ("AES-128", "Decrypt", "AES-128 Decrypt"),
    ("AES-128", "Cipher Size", "AES-128 Cipher Size"),
    ("AES-192", "Encrypt", "AES-192 Encrypt"),
    ("AES-192", "Decrypt", "AES-192 Decrypt"),
    ("AES-192", "Cipher Size", "AES-192 Cipher Size"),
    ("AES-256", "Encrypt", "AES-256 Encrypt"),
    ("AES-256", "Decrypt", "AES-256 Decrypt"),
    ("AES-256", "Cipher Size", "AES-256 Cipher Size"),
]

# Create transposed DataFrame
transposed_rows = []
for algo_name, op_name, result_key in operations:
    row = {"Algorithm": algo_name, "Operation": op_name}
    for result in results:
        size = result["Data Size"]
        if result_key in result:
            row[f"{size} bits"] = result[result_key]
    transposed_rows.append(row)

transposed_df = pd.DataFrame(transposed_rows)

# Reorder columns
column_order = ["Algorithm", "Operation"] + [f"{size} bits" for size in data_sizes]
transposed_df = transposed_df[column_order]

print("\nBenchmark Results:")
print(transposed_df.to_string(index=False))

# Save to Excel
with pd.ExcelWriter(f"benchmark_results_new_{ITERATION}.xlsx") as writer:
    transposed_df.to_excel(writer, sheet_name="Benchmark Results", index=False, float_format="%.10f")
    cpu_df.to_excel(writer, sheet_name="CPU Info", index=False, float_format="%.10f")

print(f"\nBenchmark completed! Results saved to 'benchmark_results_{ITERATION}.xlsx'.")