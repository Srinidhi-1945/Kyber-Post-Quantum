let cipher = "";
let sessionId = null;
let sent = false;
let attacked = false;

function updateUI() {

    const algo = getAlgo();

    if (algo === "kyber") {

        document.getElementById("diffieSection").style.display = "none";
        document.getElementById("kyberSection").style.display = "block";

    } else {

        document.getElementById("diffieSection").style.display = "block";
        document.getElementById("kyberSection").style.display = "none";

    }
}
function getAlgo() {
    return document.getElementById("algo").value;
}

function getMode() {
    return document.getElementById("mode").value;
}

function addStep(text) {
    const div = document.createElement("div");
    div.innerText = "➡ " + text;
    document.getElementById("steps").appendChild(div);
}

// STEP 1
async function step1() {
    const res = await fetch(`/api/step1?algo=${getAlgo()}`);
    const data = await res.json();

    //document.getElementById("bobKey").innerText = data.bob_public;
    if (getAlgo() === "dh") {
    document.getElementById("aliceKey").innerText = data.alice_public;
    document.getElementById("bobKey").innerText = data.bob_public;
    document.getElementById("malloryAlice").innerText = data.mallory_to_alice;
    document.getElementById("malloryBob").innerText = data.mallory_to_bob;
}  else {
    document.getElementById("bobKey").innerText = data.bob_public;

    // 🔥 ADD THIS LINE (VERY IMPORTANT)
    document.getElementById("kyberBobKey").innerText = data.bob_public;
}
    addStep(data.step);
}

// STEP 2
async function step2() {
    const res = await fetch("/api/step2");
    const data = await res.json();

    addStep(data.step);
}

// STEP 3
async function step3() {

    sent = false;
    attacked = false;

    const msg = document.getElementById("message").value;
    //const bobKey = document.getElementById("bobKey").innerText;

    if (getAlgo() === "kyber" && 
    document.getElementById("kyberBobKey").innerText === "-") {

    alert("⚠️ Generate keys first!");
    return;
}

    document.getElementById("bob-message").innerText = "";
    document.getElementById("intercepted").innerText = "";

    const res = await fetch("/api/step3", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            message: msg,
            algo: getAlgo()
        })
    });

    const data = await res.json();

    if (!data.encrypted) {
        console.log(data);
        alert("❌ Encryption failed");
        return;
    }
    if (getAlgo() === "kyber") {
    document.getElementById("kyberCipher").innerText = data.ciphertext;
}

    cipher = data.encrypted;

    document.getElementById("encrypted").innerText = data.encrypted;
    document.getElementById("ciphertext").innerText = data.ciphertext;
    document.getElementById("sharedKey").innerText = data.shared;
    // 🔥 FIX: ensure shared key always shows
if (!data.shared) {
    document.getElementById("sharedKey").innerText = "❌ Not generated";
}
console.log("shared Key:",data.shared);
    // 🔥 ADD THIS (DIFFIE KEYS DISPLAY)
if (getAlgo() === "dh") {

    document.getElementById("aliceKey").innerText = data.alice_public || "-";
    document.getElementById("bobKey").innerText = data.bob_public || "-";

    document.getElementById("malloryAlice").innerText = data.mallory_to_alice || "-";
    document.getElementById("malloryBob").innerText = data.mallory_to_bob || "-";
}
    addStep(data.step);
}

// STEP 4
async function step4() {

    if (!cipher) {
        alert("⚠️ Encrypt first!");
        return;
    }

    const msg = document.getElementById("message").value;

    const res = await fetch("/api/step4", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            message: msg,
            algo: getAlgo(),
            mode: getMode()
        })
    });

    const data = await res.json();
    document.getElementById("intercepted").innerText =
    data.intercepted || "❌ Not intercepted";
    // 🔥 SHOW A → M
if (data.am_cipher) {
    document.getElementById("intercepted").innerText =
        "A → M: " + data.am_cipher;
}
    // 🔥 SHOW AT MALLORY SIDE
if (data.intercepted) {
    document.getElementById("intercepted").innerText = data.intercepted;
}
    if (getAlgo() === "dh" && getMode() === "mitm") {
    document.getElementById("bob-message").innerText =
        "❌ Bob has NOT received anything (intercepted by Mallory)";
} else {
    document.getElementById("bob-message").innerText = cipher;
}
    

    addStep(data.step);

    sent = true;
}

// STEP 5
async function step5() {

    const res = await fetch(`/api/step5?algo=${getAlgo()}`);
    const data = await res.json();

    if (getAlgo() === "dh" && getMode() === "mitm" && attacked) {
        addStep("⚠️ Bob decrypting attacker-modified message");
    }

    document.getElementById("bob-message").innerText = data.message;
    addStep("📬 Bob decrypted message");
}

// ATTACK
async function attackerModify() {

    if (getAlgo() !== "dh" || getMode() !== "mitm") return;

    if (!sent) {
        alert("⚠️ Send first!");
        return;
    }

    const modified = document.getElementById("attackerMessage").value;

    const res = await fetch("/api/dh/modify", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ modified })
    });

    const data = await res.json();

    cipher = data.cipher;
    // 🔥 SHOW M → B
if (data.mb_cipher) {
    document.getElementById("bob-message").innerText =
        "M → B: " + data.mb_cipher;
}
   // document.getElementById("encrypted").innerText = data.cipher;
   // document.getElementById("ciphertext").innerText = data.cipher;
    document.getElementById("intercepted").innerText = data.cipher;
    //addStep("📡 Mallory sent modified ciphertext to Bob");
    attacked = true;

    document.getElementById("bob-message").innerText = cipher;
    

    addStep("🕵️ Mallory modified ciphertext");
}
window.onload = updateUI;