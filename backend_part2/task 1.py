# task3_final.py
# Task 3 – Multi-Signature Query Verification & Secure Delivery
# Follows Lecture 5 (RSA) + Lecture 6 (Harn) + Assignment spec

# Step 1: Harn-based signature components
def generate_secret_key(identity, d, n):
    # g_i = ID^d mod n
    return pow(identity, d, n)

def generate_partial_signature(gi, ri, m, n):
    # σ_i = g_i * r_i^m mod n
    return (gi * pow(ri, m, n)) % n

def aggregate_signatures(sig_dict, n):
    # σ = (σ_1 + σ_2 + σ_3 + σ_4) mod n
    return sum(sig_dict.values()) % n

# Step 2: RSA encryption (Procurement Officer)
def encrypt_message(msg, public_key):
    e, n = public_key
    m = int.from_bytes(str(msg).encode(), 'big')
    return pow(m, e, n)

def decrypt_message(ciphertext, private_key):
    d, n = private_key
    m = pow(ciphertext, d, n)
    return int.from_bytes(m.to_bytes((m.bit_length() + 7) // 8, 'big'), 'big')

# Step 3: Key values from your key list (IDs, d, n, r values)
inventories = {
    "Inventory_A": {"ID": 126, "r": 621,
        "d": 1359908369143705140915574118545189095499406328097208654560783239847135545871732205365749449,
        "n": 1510655732025614931618473113490936936007010876086492730422218817435607919502486239158421141},

    "Inventory_B": {"ID": 127, "r": 721,
        "d": 385554006345823895959076237099978492568148088900455562304224630322221920712351462955463639,
        "n": 1043592637028925963812797464507113356509508109284032337574598025668423558948865906670023913},

    "Inventory_C": {"ID": 128, "r": 821,
        "d": 59718784423799151459849899904574018009709157083418928937386561733370611446246317425827993,
        "n": 916910444232677830583692042601026220327574396695137541357168363411849184127399957852764263},

    "Inventory_D": {"ID": 129, "r": 921,
        "d": 456826729944023441542435595542382246049075898780851000828935272347310661251862889992482579,
        "n": 1713861192202060574132658988016647849520234158153264986650265683470192580439042716358687419}
}

procurement_officer = {
    "e": 106506253943651610547613,
    "n": 1251860471424789052966525878914535614061432909643973429720664756803786476370927527592886331,
    "d": 1011366078496009346845383448209985404012306581197309959773151470567275109692022512612101173
}

# Step 4: Inventory record (hardcoded for item ID "004")
item_quantities = {
    "Inventory_A": 12,
    "Inventory_B": 18,
    "Inventory_C": 0,
    "Inventory_D": 30
}

# Step 5: Execution
def run_task3_query():
    sigs = {}
    total_qty = 0

    for inv, data in inventories.items():
        qty = item_quantities[inv]
        total_qty += qty
        gi = generate_secret_key(data["ID"], data["d"], data["n"])
        sig = generate_partial_signature(gi, data["r"], qty, data["n"])
        sigs[inv] = sig

    # PKG n used for aggregated signature modulus
    pkg_n = 954088232425229706382520201245618381050107066567161988535764573189666148989564060702644969
    final_sig = aggregate_signatures(sigs, pkg_n)

    # Step 6: Encrypt result
    encrypted_qty = encrypt_message(total_qty, (procurement_officer["e"], procurement_officer["n"]))

    # Step 7: Decrypt result
    decrypted_qty = decrypt_message(encrypted_qty, (procurement_officer["d"], procurement_officer["n"]))

    return {
        "total_quantity": total_qty,
        "multi_signature": final_sig,
        "encrypted_quantity": encrypted_qty,
        "decrypted_quantity": decrypted_qty
    }

# Final Output
if __name__ == "__main__":
    result = run_task3_query()
    for k, v in result.items():
        print(f"{k}: {v}")
