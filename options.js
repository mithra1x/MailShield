document.getElementById("saveBtn").addEventListener("click", async () => {
  const autoScan = document.getElementById("autoScan").checked;
  const text = document.getElementById("userTrustedDomains").value.trim();
  const userTrustedDomains = text ? text.split(/\n/).map((s) => s.trim()).filter(Boolean) : [];
  await chrome.storage.sync.set({ autoScan, userTrustedDomains });
  const el = document.getElementById("savedMsg");
  el.classList.remove("hidden");
  el.textContent = "Options saved.";
  setTimeout(() => el.classList.add("hidden"), 2000);
});

async function load() {
  const { autoScan, userTrustedDomains } = await chrome.storage.sync.get(["autoScan", "userTrustedDomains"]);
  document.getElementById("autoScan").checked = !!autoScan;
  const list = Array.isArray(userTrustedDomains) ? userTrustedDomains : (typeof userTrustedDomains === "string" ? userTrustedDomains.split(/\n/) : []);
  document.getElementById("userTrustedDomains").value = list.join("\n");
}
load();
