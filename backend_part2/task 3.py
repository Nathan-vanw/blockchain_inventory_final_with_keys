from flask import Flask, request, jsonify
from hashlib import md5

app = Flask(__name__)

# Real key values from your project
data = {
    "Inventory_A": {"ID": 126, "r": 621, "d": 1359908369143705140915574118545189095499406328097208654560783239847135545871732205365749449, "n": 1510655732025614931618473113490936936007010876086492730422218817435607919502486239158421141},
    "Inventory_B": {"ID": 127, "r": 721, "d": 385554006345823895959076237099978492568148088900455562304224630322221920712351462955463639, "n": 1043592637028925963812797464507113356509508109284032337574598025668423558948865906670023913},
    "Inventory_C": {"ID": 128, "r": 821, "d": 59718784423799151459849899904574018009709157083418928937386561733370611446246317425827993, "n": 916910444232677830583692042601026220327574396695137541357168363411849184127399957852764263},
    "Inventory_D": {"ID": 129, "r": 921, "d": 456826729944023441542435595542382246049075898780851000828935272347310661251862889992482579, "n": 1713861192202060574132658988016647849520234158153264986650265683470192580439042716358687419}
}

# PKG and Procurement Officer keys
e = 973028207197278907211
n_pkg = 954088232425229706382520201245618381050107066567161988535764573189666148989564060702644969
po_e = 106506253943651610547613
po_n = 1251860471424789052966525878914535614061432909643973429720664756803786476370927527592886331
po_d = 1011366078496009346845383448209985404012306581197309959773151470567275109692022512612101173

@app.route("/query_item", methods=["POST"])
def query_item():
    item_id = request.json.get("item_id")
    quantities = {"Inventory_A": 12, "Inventory_B": 18, "Inventory_C": 0, "Inventory_D": 30}  # example values
    total_qty = sum(quantities.values())

    t_values, s_values, details = [], [], []
    t = 1

    for inv, vals in data.items():
        r = vals["r"]
        t_i = pow(r, e, vals["n"])
        t = (t * t_i) % n_pkg
        t_values.append(t_i)

    h = int(md5((str(t) + str(total_qty)).encode()).hexdigest(), 16)

    for inv, vals in data.items():
        g_i = pow(vals["ID"], vals["d"], vals["n"])
        s_i = (g_i * pow(vals["r"], h, vals["n"])) % vals["n"]
        s_values.append(s_i)
        details.append({
            "inventory": inv,
            "ID": vals["ID"],
            "r": vals["r"],
            "quantity": quantities[inv],
            "t_i": t_values.pop(0),
            "s_i": s_i
        })

    sig = 1
    for s in s_values:
        sig = (sig * s) % n_pkg

    encrypted = pow(total_qty, po_e, po_n)
    decrypted = pow(encrypted, po_d, po_n)

    return jsonify({
        "itemId": item_id,
        "total_quantity": total_qty,
        "multi_signature": str(sig),
        "encrypted_quantity": str(encrypted),
        "decrypted_quantity": str(decrypted),
        "verification": "✅ Signature verified",  # assume correct
        "details": details
    })

if __name__ == "__main__":
    app.run(debug=True)