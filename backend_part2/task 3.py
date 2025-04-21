import json
import hashlib

# === Load Hardcoded Keys from JSON File ===
with open("all_keys.json") as f:
    keys = json.load(f)

inventories = keys["Inventories"]
harn = keys["HarnKeys"]
IDs = harn["IDs"]
Randoms = harn["Randoms"]

# === Step 1: Generate g_i = ID^d mod n for each node ===
def generate_secret_key(ID, d, n):
    return pow(ID, d, n)

# === Step 2: t_i = r_i^e mod n ===
def generate_commitment(r, e, n):
    return pow(r, e, n)

# === Step 3: Combine commitments t = t1 * t2 * ... mod n ===
def combine_commitments(t_list, n):
    t = 1
    for ti in t_list:
        t = (t * ti) % n
    return t

# === Step 4: Compute MD5 hash of (t || message) ===
def compute_hash(t, message):
    digest = hashlib.md5((str(t) + str(message)).encode()).hexdigest()
    return int(digest, 16)

# === Step 5: Partial signature s_i = g_i * r_i^H mod n ===
def generate_partial_signature(g, r, h, n):
    return (g * pow(r, h, n)) % n

# === Step 6: Aggregate signature s = s1 * s2 * s3 * s4 mod n ===
def aggregate_signature(s_list, n):
    s = 1
    for si in s_list:
        s = (s * si) % n
    return s

# === Step 7: RSA Encrypt ===
def rsa_encrypt(message, e, n):
    m = int.from_bytes(str(message).encode(), 'big')
    return pow(m, e, n)

# === Step 8: RSA Decrypt ===
def rsa_decrypt(cipher, d, n):
    m = pow(cipher, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

# === Step 9: Multi-Signature Verification ===
def verify_signature(s, e, n, ids, t, h):
    lhs = pow(s, e, n)
    id_product = 1
    for ID in ids:
        id_product = (id_product * ID) % n
    rhs = (id_product * pow(t, h, n)) % n
    return lhs == rhs

# === Core Flow ===
def run_task3(item_id="004"):
    quantities = {
        "Inventory_A": 12,
        "Inventory_B": 18,
        "Inventory_C": 0,
        "Inventory_D": 30
    }

    total_quantity = sum(quantities.values())
    e_pkg = harn["PKG"]["e"]
    n_pkg = harn["PKG"]["n"]
    ids = list(IDs.values())

    # Step A: Generate t_i, g_i, s_i
    t_list, s_list = [], []
    for name in inventories:
        ID = IDs[name]
        d = inventories[name]["d"]
        n = inventories[name]["n"]
        r = Randoms[name]
        g = generate_secret_key(ID, d, n)
        t_i = generate_commitment(r, e_pkg, n)
        t_list.append(t_i)
        h = compute_hash(combine_commitments(t_list, n_pkg), total_quantity)
        s_i = generate_partial_signature(g, r, h, n)
        s_list.append(s_i)

    t = combine_commitments(t_list, n_pkg)
    h = compute_hash(t, total_quantity)
    signature = aggregate_signature(s_list, n_pkg)

    # Encrypt with Procurement Officer's public key
    po_e = harn["ProcurementOfficer"]["e"]
    po_n = harn["ProcurementOfficer"]["n"]
    po_d = harn["ProcurementOfficer"]["d"]
    ciphertext = rsa_encrypt(total_quantity, po_e, po_n)
    decrypted = rsa_decrypt(ciphertext, po_d, po_n)

    # Verify signature
    is_valid = verify_signature(signature, e_pkg, n_pkg, ids, t, h)

    print("=== Task 3 Results ===")
    print(f"Item ID Queried:         {item_id}")
    print(f"Total Quantity:          {total_quantity}")
    print(f"Multi-Signature (σ):     {signature}")
    print(f"Commitment (t):          {t}")
    print(f"Hash H(t, m):            {h}")
    print(f"Encrypted Quantity:      {ciphertext}")
    print(f"Decrypted Quantity:      {decrypted}")
    print(f"Signature Verified:      {'✅ Valid' if is_valid else '❌ Invalid'}")

# === Run Task 3 ===
if __name__ == "__main__":
    run_task3()
