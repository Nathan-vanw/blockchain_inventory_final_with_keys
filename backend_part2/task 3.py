# task3_final.py
import hashlib

# Step 1: Harn identity-based secret key generation
def generate_secret_key(ID, d, n):
    return pow(ID, d, n)  # g_i = ID^d mod n

# Step 2: Random commitment t_i = r_i^e mod n
def generate_commitment(r, e, n):
    return pow(r, e, n)

# Step 3: Combine commitments t = t1 * t2 * ... mod n
def combine_commitments(t_list, n):
    t = 1
    for ti in t_list:
        t = (t * ti) % n
    return t

# Step 4: Hash the combined t and message m
def compute_hash(t, message):
    hash_input = str(t) + str(message)
    digest = hashlib.md5(hash_input.encode()).hexdigest()
    return int(digest, 16)  # Convert hex to decimal

# Step 5: Generate partial signature: s_i = g_i * r_i^H mod n
def generate_partial_signature(g, r, h, n):
    return (g * pow(r, h, n)) % n

# Step 6: Aggregate final signature: s = s1 * s2 * s3 * s4 mod n
def aggregate_signature(s_list, n):
    s = 1
    for si in s_list:
        s = (s * si) % n
    return s

# Step 7: RSA encryption
def rsa_encrypt(message, e, n):
    m = int.from_bytes(str(message).encode(), 'big')
    return pow(m, e, n)

# Step 8: RSA decryption
def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

# Step 9: Multi-signature verification
def verify_signature(s, e, n, ids, t, h):
    lhs = pow(s, e, n)
    product_ids = 1
    for ID in ids:
        product_ids = (product_ids * ID) % n
    rhs = (product_ids * pow(t, h, n)) % n
    return lhs == rhs
