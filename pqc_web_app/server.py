'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))


def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()


# ================= DIFFIE (256-BIT HEX) =================
def dh_generate():
    # 256-bit prime (secp256k1 prime)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    g = 2

    # 256-bit private keys
    a = secrets.randbits(256)
    b = secrets.randbits(256)

    # public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # shared keys
    key_am = pow(B, a, p)
    key_mb = pow(A, b, p)

    # format as fixed 256-bit hex
    def to_hex(x):
        return "0x" + format(x, '064x')

    return {
        "A": to_hex(A),
        "B": to_hex(B),
        "M1": to_hex(secrets.randbits(256)),
        "M2": to_hex(secrets.randbits(256)),
        "key_am": to_hex(key_am),
        "key_mb": to_hex(key_mb)
    }


# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo")

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated (256-bit HEX)",
            "alice_public": dh["A"],
            "bob_public": dh["B"],
            "mallory_to_alice": dh["M1"],
            "mallory_to_bob": dh["M2"]
        })

    # ===== KYBER =====
    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Bob generated Kyber keys",
        "bob_public": pk.hex()[:60] + "...",
        "kyber_public": pk.hex()[:60] + "..."
    })


# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Bob shared public key"})


# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":
        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        shared, ct = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE (256-bit HEX) =====
    elif algo == "dh":
        if "key_am" not in session_data:
            dh = dh_generate()
            session_data.update(dh)

        key_int = int(session_data["key_am"], 16)

        encrypted = aes_encrypt(message, key_int)

        session_data["cipher_am"] = encrypted
        session_data["shared_key"] = session_data["key_am"]

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex()[:60] + "...",
            "shared": session_data["shared_key"],
            "alice_public": session_data["A"],
            "bob_public": session_data["B"],
            "mallory_to_alice": session_data["M1"],
            "mallory_to_bob": session_data["M2"],
            "step": "🔐 DH encryption done (256-bit)"
        })


# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    if algo == "dh":
        if mode == "mitm":
            cipher = session_data.get("cipher_am")

            session_data["intercepted_cipher"] = cipher

            return jsonify({
                "cipher": None,
                "intercepted": cipher.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "intercepted": "❌ Not intercepted",
            "step": "📡 Sent securely"
        })

    elif algo == "kyber":
        if mode == "mitm":
            original_ct = session_data.get("kyber_ct")

            tampered_ct = b"00" + original_ct[:10]
            session_data["kyber_fake_ct"] = tampered_ct
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": original_ct.hex()[:60] + "...",
                "tampered": tampered_ct.hex()[:60] + "...",
                "step": "🕵️ Mallory tried to tamper"
            })

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "intercepted": "❌ Not intercepted",
            "step": "📡 Sent securely using Kyber"
        })


# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_am"],
            int(session_data["shared_key"], 16)
        )
        return jsonify({"message": decrypted})

    elif algo == "kyber":
        if session_data.get("kyber_tampered"):
            return jsonify({"message": "🚫 Attack detected"})

        shared = Kyber512.decaps(
            session_data["sk"],
            session_data["kyber_ct"]
        )

        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            shared
        )

        return jsonify({"message": decrypted})


# ================= MODIFY =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    modified = request.json.get("modified")

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        int(session_data["shared_key"], 16)
    )

    new_text = modified if modified else plaintext

    new_cipher = aes_encrypt(
        new_text,
        int(session_data["shared_key"], 16)
    )

    session_data["cipher_am"] = new_cipher

    return jsonify({
        "cipher": new_cipher.hex()
    })


# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)


# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)
    key_mb = pow(B, m2, p)

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am, "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":

        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        ct, shared = Kyber512.encaps(session_data["pk"])  # ✅ FIXED ORDER
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    elif algo == "dh":

        key_am = session_data["key_am"]
        encrypted = aes_encrypt(message, key_am)

        session_data["cipher_am"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex(),
            "shared": str(key_am),
            "step": "🔐 Diffie encryption done"
        })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]
            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    elif algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # ===== KYBER MITM =====
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # ===== DIFFIE MITM =====
    if session_data.get("cipher_to_bob") and session_data.get("dh_key"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # ===== DIFFIE SECURE =====
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # ===== KYBER SECURE =====
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)   # Alice ↔ Mallory
    key_mb = pow(B, m2, p)   # Mallory ↔ Bob

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":

        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        ct, shared = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    elif algo == "dh":

        key_am = session_data["key_am"]
        encrypted = aes_encrypt(message, key_am)

        session_data["cipher_am"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex(),
            "shared": str(key_am),
            "step": "🔐 Diffie encryption done"
        })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        # 🔴 MITM
        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            # Alice → Mallory ONLY
            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            # 🚫 stop direct delivery
            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted (waiting to modify)"
            })

        # 🟢 SECURE
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    elif algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # 🔴 KYBER ATTACK
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # 🔴 DIFFIE MITM (HIGHEST PRIORITY)
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # 🟢 DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # 🟢 KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    # Mallory decrypts Alice message
    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    # Mallory → Bob new key
    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    # 🔥 FINAL FLOW
    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    # overwrite (important)
    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    #the below code is working but secret key is not getting generated
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)  # Alice ↔ Mallory
    key_mb = pow(B, m2, p)  # Mallory ↔ Bob

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")

    # ===== KYBER =====
    if algo == "kyber":
        ct, shared = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    key_am = session_data["key_am"]
    encrypted = aes_encrypt(message, key_am)

    session_data["cipher_am"] = encrypted

    return jsonify({
        "encrypted": encrypted.hex(),
        "ciphertext": encrypted.hex(),
        "shared": str(key_am),
        "step": "🔐 Diffie encryption done"
    })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            # ❌ stop Alice → Bob
            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        # ✅ secure
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    if algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    # Mallory decrypts Alice message
    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    # 🔥 Mallory → Bob FINAL
    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    # overwrite flow (IMPORTANT)
    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # 🔴 KYBER MITM
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # 🔴 DIFFIE MITM (PRIORITY)
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # 🟢 DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # 🟢 KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    try:
        key_bytes = sha256(str(key).encode()).digest()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16).decode()
    except Exception:
        # 🔥 KEY MISMATCH / ATTACK DETECTED
        return None

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)
    key_mb = pow(B, m2, p)

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")

    # ===== KYBER =====
    if algo == "kyber":
        ct, shared = Kyber512.encaps(session_data["pk"])

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["shared_key"] = shared

        encrypted = aes_encrypt(message, shared)
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    '''key_am = session_data.get("key_am")

    if not key_am:
        dh = dh_generate()
        session_data.update(dh)
        key_am = dh["key_am"]

    session_data["shared_key"] = key_am

    encrypted = aes_encrypt(message, key_am)
    session_data["cipher_am"] = encrypted

    return jsonify({
        "encrypted": encrypted.hex(),
        "ciphertext": encrypted.hex(),
        "shared": str(key_am),
        "step": "🔐 Diffie encryption done"
    })
'''

'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))


def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()


# ================= DIFFIE (256-BIT HEX) =================
def dh_generate():
    # 256-bit prime (secp256k1 prime)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    g = 2

    # 256-bit private keys
    a = secrets.randbits(256)
    b = secrets.randbits(256)

    # public keys
    A = pow(g, a, p)
    B = pow(g, b, p)

    # shared keys
    key_am = pow(B, a, p)
    key_mb = pow(A, b, p)

    # format as fixed 256-bit hex
    def to_hex(x):
        return "0x" + format(x, '064x')

    return {
        "A": to_hex(A),
        "B": to_hex(B),
        "M1": to_hex(secrets.randbits(256)),
        "M2": to_hex(secrets.randbits(256)),
        "key_am": to_hex(key_am),
        "key_mb": to_hex(key_mb)
    }


# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo")

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated (256-bit HEX)",
            "alice_public": dh["A"],
            "bob_public": dh["B"],
            "mallory_to_alice": dh["M1"],
            "mallory_to_bob": dh["M2"]
        })

    # ===== KYBER =====
    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Bob generated Kyber keys",
        "bob_public": pk.hex()[:60] + "...",
        "kyber_public": pk.hex()[:60] + "..."
    })


# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Bob shared public key"})


# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":
        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        shared, ct = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE (256-bit HEX) =====
    elif algo == "dh":
        if "key_am" not in session_data:
            dh = dh_generate()
            session_data.update(dh)

        key_int = int(session_data["key_am"], 16)

        encrypted = aes_encrypt(message, key_int)

        session_data["cipher_am"] = encrypted
        session_data["shared_key"] = session_data["key_am"]

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex()[:60] + "...",
            "shared": session_data["shared_key"],
            "alice_public": session_data["A"],
            "bob_public": session_data["B"],
            "mallory_to_alice": session_data["M1"],
            "mallory_to_bob": session_data["M2"],
            "step": "🔐 DH encryption done (256-bit)"
        })


# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    if algo == "dh":
        if mode == "mitm":
            cipher = session_data.get("cipher_am")

            session_data["intercepted_cipher"] = cipher

            return jsonify({
                "cipher": None,
                "intercepted": cipher.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "intercepted": "❌ Not intercepted",
            "step": "📡 Sent securely"
        })

    elif algo == "kyber":
        if mode == "mitm":
            original_ct = session_data.get("kyber_ct")

            tampered_ct = b"00" + original_ct[:10]
            session_data["kyber_fake_ct"] = tampered_ct
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": original_ct.hex()[:60] + "...",
                "tampered": tampered_ct.hex()[:60] + "...",
                "step": "🕵️ Mallory tried to tamper"
            })

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "intercepted": "❌ Not intercepted",
            "step": "📡 Sent securely using Kyber"
        })


# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_am"],
            int(session_data["shared_key"], 16)
        )
        return jsonify({"message": decrypted})

    elif algo == "kyber":
        if session_data.get("kyber_tampered"):
            return jsonify({"message": "🚫 Attack detected"})

        shared = Kyber512.decaps(
            session_data["sk"],
            session_data["kyber_ct"]
        )

        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            shared
        )

        return jsonify({"message": decrypted})


# ================= MODIFY =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    modified = request.json.get("modified")

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        int(session_data["shared_key"], 16)
    )

    new_text = modified if modified else plaintext

    new_cipher = aes_encrypt(
        new_text,
        int(session_data["shared_key"], 16)
    )

    session_data["cipher_am"] = new_cipher

    return jsonify({
        "cipher": new_cipher.hex()
    })


# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)


# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)
    key_mb = pow(B, m2, p)

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am, "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":

        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        ct, shared = Kyber512.encaps(session_data["pk"])  # ✅ FIXED ORDER
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    elif algo == "dh":

        key_am = session_data["key_am"]
        encrypted = aes_encrypt(message, key_am)

        session_data["cipher_am"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex(),
            "shared": str(key_am),
            "step": "🔐 Diffie encryption done"
        })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]
            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    elif algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # ===== KYBER MITM =====
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # ===== DIFFIE MITM =====
    if session_data.get("cipher_to_bob") and session_data.get("dh_key"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # ===== DIFFIE SECURE =====
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # ===== KYBER SECURE =====
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)   # Alice ↔ Mallory
    key_mb = pow(B, m2, p)   # Mallory ↔ Bob

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")
    mode = request.json.get("mode")

    # ===== KYBER =====
    if algo == "kyber":

        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        ct, shared = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    elif algo == "dh":

        key_am = session_data["key_am"]
        encrypted = aes_encrypt(message, key_am)

        session_data["cipher_am"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex(),
            "shared": str(key_am),
            "step": "🔐 Diffie encryption done"
        })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        # 🔴 MITM
        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            # Alice → Mallory ONLY
            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            # 🚫 stop direct delivery
            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted (waiting to modify)"
            })

        # 🟢 SECURE
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    elif algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        # secure
        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # 🔴 KYBER ATTACK
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # 🔴 DIFFIE MITM (HIGHEST PRIORITY)
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # 🟢 DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # 🟢 KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    # Mallory decrypts Alice message
    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    # Mallory → Bob new key
    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    # 🔥 FINAL FLOW
    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    # overwrite (important)
    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    #the below code is working but secret key is not getting generated
    
'''from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 16).decode()

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)  # Alice ↔ Mallory
    key_mb = pow(B, m2, p)  # Mallory ↔ Bob

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"

    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")

    # ===== KYBER =====
    if algo == "kyber":
        ct, shared = Kyber512.encaps(session_data["pk"])
        encrypted = aes_encrypt(message, shared)

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    key_am = session_data["key_am"]
    encrypted = aes_encrypt(message, key_am)

    session_data["cipher_am"] = encrypted

    return jsonify({
        "encrypted": encrypted.hex(),
        "ciphertext": encrypted.hex(),
        "shared": str(key_am),
        "step": "🔐 Diffie encryption done"
    })

# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            # ❌ stop Alice → Bob
            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        # ✅ secure
        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    if algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= MODIFY (MITM DIFFIE) =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    # Mallory decrypts Alice message
    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    # 🔥 Mallory → Bob FINAL
    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    # overwrite flow (IMPORTANT)
    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # 🔴 KYBER MITM
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # 🔴 DIFFIE MITM (PRIORITY)
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # 🟢 DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["key_am"]
        )
        return jsonify({"message": decrypted})

    # 🟢 KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''
    
    
    
    
    
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from kyber_py.kyber import Kyber512
from hashlib import sha256
import secrets
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__, static_folder="ui", static_url_path="")
CORS(app)

session_data = {}

# ================= AES =================
def aes_encrypt(message, key):
    key_bytes = sha256(str(key).encode()).digest()
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    return cipher.encrypt(pad(message.encode(), 16))

def aes_decrypt(ciphertext, key):
    try:
        key_bytes = sha256(str(key).encode()).digest()
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), 16).decode()
    except Exception:
        # 🔥 KEY MISMATCH / ATTACK DETECTED
        return None

# ================= DIFFIE =================
def dh_generate():
    p = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF",
        16
    )
    g = 2

    a = secrets.randbits(256)
    b = secrets.randbits(256)
    m1 = secrets.randbits(256)
    m2 = secrets.randbits(256)

    A = pow(g, a, p)
    B = pow(g, b, p)
    M1 = pow(g, m1, p)
    M2 = pow(g, m2, p)

    key_am = pow(M1, a, p)
    key_mb = pow(B, m2, p)

    return {
        "A": A, "B": B, "M1": M1, "M2": M2,
        "key_am": key_am,
        "key_mb": key_mb
    }

# ================= STEP 1 =================
@app.route("/api/step1")
def step1():
    algo = request.args.get("algo") or "kyber"
    # 🔥 RESET OLD DATA (VERY IMPORTANT)
    session_data.clear()
    if algo == "dh":
        dh = dh_generate()
        session_data.update(dh)

        return jsonify({
            "step": "🔑 Diffie keys generated",
            "alice_public": str(dh["A"]),
            "bob_public": str(dh["B"]),
            "mallory_to_alice": str(dh["M1"]),
            "mallory_to_bob": str(dh["M2"])
        })

    pk, sk = Kyber512.keygen()
    session_data["pk"] = pk
    session_data["sk"] = sk

    return jsonify({
        "step": "🔑 Kyber keys generated",
        "bob_public": pk.hex()[:60] + "..."
    })

# ================= STEP 2 =================
@app.route("/api/step2")
def step2():
    return jsonify({"step": "📡 Public key shared"})

# ================= STEP 3 =================
@app.route("/api/step3", methods=["POST"])
def step3():
    message = request.json.get("message", "")
    algo = request.json.get("algo")

    # ===== KYBER =====
    if algo == "kyber":
        '''ct, shared = Kyber512.encaps(session_data["pk"])

        session_data["kyber_ct"] = ct
        session_data["kyber_shared"] = shared
        session_data["shared_key"] = shared

        encrypted = aes_encrypt(message, shared)
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",
            "step": "🔐 Kyber encryption done"
        })'''
        
        # ===== KYBER =====
        shared , ct = Kyber512.encaps(session_data["pk"])
        # 🔥 STORE CIPHERTEXT (MISSING LINE)
        session_data["kyber_ct"] = ct
        # 🔥 ENSURE KEYPAIR EXISTS
        if "pk" not in session_data:
            pk, sk = Kyber512.keygen()
            session_data["pk"] = pk
            session_data["sk"] = sk

        # 🔥 STORE SHARED KEY PROPERLY
        session_data["kyber_shared"] = shared
        session_data["shared_key"] = shared

        encrypted = aes_encrypt(message, shared)
        session_data["kyber_encrypted"] = encrypted

        return jsonify({
            "encrypted": encrypted.hex(),
            "ciphertext": ct.hex()[:60] + "...",
            "shared": shared.hex()[:60] + "...",  # 🔥 SHOW
            "step": "🔐 Kyber encryption done"
        })

    # ===== DIFFIE =====
    '''key_am = session_data.get("key_am")

    if not key_am:
        dh = dh_generate()
        session_data.update(dh)
        key_am = dh["key_am"]

    session_data["shared_key"] = key_am

    encrypted = aes_encrypt(message, key_am)
    session_data["cipher_am"] = encrypted

    return jsonify({
        "encrypted": encrypted.hex(),
        "ciphertext": encrypted.hex(),
        "shared": str(key_am),
        "step": "🔐 Diffie encryption done"
    })
'''

# ===== DIFFIE =====
    key_am = session_data.get("key_am")

# 🔥 ensure key exists
    if not key_am:
        dh = dh_generate()
        session_data.update(dh)
        key_am = dh["key_am"]

# 🔥 STORE SHARED KEY (IMPORTANT)
    session_data["shared_key"] = key_am

    encrypted = aes_encrypt(message, key_am)
    session_data["cipher_am"] = encrypted

    return jsonify({
        "encrypted": encrypted.hex(),
            "ciphertext": encrypted.hex(),
            "shared": str(key_am),   # 🔥 SHOW IN UI
            "step": "🔐 Diffie encryption done"
})
# ================= STEP 4 =================
@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    if algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= MODIFY =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # KYBER MITM
    if request.args.get("algo") == "kyber" and session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # DIFFIE MITM
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["shared_key"]
        )
        return jsonify({"message": decrypted})

    # KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)
# ================= STEP 4 =================
'''@app.route("/api/step4", methods=["POST"])
def step4():
    mode = request.json.get("mode")
    algo = request.json.get("algo")

    # ===== DIFFIE =====
    if algo == "dh":

        if mode == "mitm":
            cipher_am = session_data["cipher_am"]

            session_data["mallory_received"] = cipher_am
            session_data["sent"] = True

            session_data.pop("cipher_to_bob", None)

            return jsonify({
                "cipher": None,
                "intercepted": cipher_am.hex(),
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["cipher_am"]

        return jsonify({
            "cipher": session_data["cipher_am"].hex(),
            "step": "📡 Sent securely"
        })

    # ===== KYBER =====
    if algo == "kyber":

        if mode == "mitm":
            session_data["kyber_tampered"] = True

            return jsonify({
                "cipher": None,
                "intercepted": session_data["kyber_ct"].hex()[:60] + "...",
                "step": "🕵️ Mallory intercepted"
            })

        session_data["cipher_to_bob"] = session_data["kyber_encrypted"]

        return jsonify({
            "cipher": session_data["kyber_encrypted"].hex(),
            "step": "📡 Sent securely (Kyber)"
        })

# ================= MODIFY =================
@app.route("/api/dh/modify", methods=["POST"])
def modify():
    data = request.json

    plaintext = aes_decrypt(
        session_data["cipher_am"],
        session_data["key_am"]
    )

    new_text = data.get("modified", plaintext)

    key_mb = secrets.randbits(128)
    new_cipher = aes_encrypt(new_text, key_mb)

    session_data["dh_key"] = key_mb
    session_data["cipher_to_bob"] = new_cipher
    session_data["sent_to_bob"] = True

    session_data["cipher_am"] = new_cipher
    session_data["key_am"] = key_mb

    return jsonify({
        "cipher": new_cipher.hex()
    })

# ================= STEP 5 =================
@app.route("/api/step5")
def step5():
    algo = request.args.get("algo")

    # KYBER MITM
    if session_data.get("kyber_tampered"):
        return jsonify({
            "message": "🚫 Key mismatch: attacker modified ciphertext"
        })

    # DIFFIE MITM
    if session_data.get("sent_to_bob"):
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["dh_key"]
        )
        return jsonify({"message": decrypted})

    # DIFFIE SECURE
    if algo == "dh":
        decrypted = aes_decrypt(
            session_data["cipher_to_bob"],
            session_data["shared_key"]
        )
        return jsonify({"message": decrypted})

    # KYBER SECURE
    if algo == "kyber":
        decrypted = aes_decrypt(
            session_data["kyber_encrypted"],
            session_data["kyber_shared"]
        )
        return jsonify({"message": decrypted})

    return jsonify({"message": "❌ Error"})

# ================= UI =================
@app.route("/")
def index():
    return send_from_directory("ui", "index.html")

@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)

# ================= RUN =================
if __name__ == "__main__":
    print("🔥 Server running at http://localhost:5000")
    app.run(debug=True)'''