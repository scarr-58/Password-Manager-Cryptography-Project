import "./style.css";
import { Keychain } from "./password-manager.js";

const $ = (id) => document.getElementById(id);
const say = (id, text, ok) => { const e = $(id); e.textContent = text; e.className = "msg " + (ok ? "ok" : "err"); };
const busy = (form, on) => form.querySelectorAll("button").forEach((b) => (b.disabled = on));
const msgOf = (e) => (typeof e === "string" ? e : e?.message || "Something went wrong.");

// the encrypted dump (data + checksum) lives in localStorage
const store = {
  get() { try { return JSON.parse(localStorage.getItem("vault")); } catch { return null; } },
  put(v) { try { localStorage.setItem("vault", JSON.stringify(v)); } catch {} },
};
let kc = null;
const save = async () => { const [data, checksum] = await kc.dump(); store.put({ data, checksum }); };

function show(view) {
  ["setup", "unlock", "vault"].forEach((v) => ($(v).hidden = v !== view));
  $("lock").hidden = view !== "vault";
  $("state").textContent = view === "vault" ? "Your vault is open." : view === "unlock" ? "Your vault is locked." : "Create a vault to get started.";
  $("result").hidden = true; $("dump").hidden = true;
}
show(store.get() ? "unlock" : "setup");

$("fSetup").onsubmit = async (e) => {
  e.preventDefault();
  if ($("m1").value !== $("m2").value) return say("mSetup", "The passwords don’t match. Enter the same password twice.");
  busy(e.target, true);
  kc = await Keychain.init($("m1").value); await save();
  e.target.reset(); busy(e.target, false); show("vault"); say("mVault", "Vault created successfully.", true);
};
$("fUnlock").onsubmit = async (e) => {
  e.preventDefault(); busy(e.target, true);
  const saved = store.get();
  try { kc = await Keychain.load($("mu").value, saved.data, saved.checksum); }
  catch (err) { busy(e.target, false); return say("mUnlock", msgOf(err) + "."); }
  busy(e.target, false); e.target.reset(); show("vault"); say("mVault", "Vault unlocked.", true);
};
$("fAdd").onsubmit = async (e) => {
  e.preventDefault();
  const n = $("aN").value.trim();
  try { await kc.set(n, $("aP").value); await save(); say("mVault", "Saved a password for “" + n + "”.", true); e.target.reset(); }
  catch (err) { say("mVault", msgOf(err) + "."); }
};
$("fGet").onsubmit = async (e) => {
  e.preventDefault();
  const n = $("gN").value.trim();
  try {
    const p = await kc.get(n);
    if (p === null) { $("result").hidden = true; return say("mVault", "No login found for “" + n + "”. Check the account name."); }
    $("rP").value = p; $("rP").type = "password"; $("show").textContent = "Show"; $("result").hidden = false;
    say("mVault", "Found the password for “" + n + "”.", true);
  } catch (err) { say("mVault", msgOf(err) + "."); }
};
$("show").onclick = () => { const h = $("rP").type === "password"; $("rP").type = h ? "text" : "password"; $("show").textContent = h ? "Hide" : "Show"; };
$("copy").onclick = async () => {
  try { await navigator.clipboard.writeText($("rP").value); say("mVault", "Password copied.", true); }
  catch { say("mVault", "Copy isn’t available here. Use Show and copy it by hand."); }
};
$("fDel").onsubmit = async (e) => {
  e.preventDefault();
  const n = $("dN").value.trim();
  if (await kc.remove(n)) { await save(); say("mVault", "Removed the login for “" + n + "”.", true); e.target.reset(); }
  else say("mVault", "No login found for “" + n + "”. Check the account name.");
};
$("export").onclick = async () => {
  const [data, checksum] = await kc.dump();
  $("dump").value = JSON.stringify({ data, checksum }, null, 2); $("dump").hidden = false; $("dump").select();
  say("mVault", "Vault exported. Copy the text below and keep it safe.", true);
};
$("lock").onclick = () => { kc = null; $("rP").value = ""; show("unlock"); say("mUnlock", "Vault locked.", true); };
