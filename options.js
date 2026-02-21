document.getElementById("saveBtn").addEventListener("click", async () => {
  const autoScan = document.getElementById("autoScan").checked;
  const domainsText = document.getElementById("userTrustedDomains").value.trim();
  const sendersText = document.getElementById("userTrustedSenders").value.trim();
  const userTrustedDomains = domainsText ? domainsText.split(/\n/).map((s) => s.trim()).filter(Boolean) : [];
  const userTrustedSenders = sendersText ? sendersText.split(/\n/).map((s) => s.trim().toLowerCase()).filter(Boolean) : [];
  await chrome.storage.sync.set({ autoScan, userTrustedDomains, userTrustedSenders });
  const el = document.getElementById("savedMsg");
  el.classList.remove("hidden");
  el.textContent = "Options saved.";
  setTimeout(() => el.classList.add("hidden"), 2000);
});

async function load() {
  const { autoScan, userTrustedDomains, userTrustedSenders } = await chrome.storage.sync.get(["autoScan", "userTrustedDomains", "userTrustedSenders"]);
  document.getElementById("autoScan").checked = !!autoScan;
  const domainList = Array.isArray(userTrustedDomains) ? userTrustedDomains : (typeof userTrustedDomains === "string" ? userTrustedDomains.split(/\n/) : []);
  document.getElementById("userTrustedDomains").value = domainList.join("\n");
  const senderList = Array.isArray(userTrustedSenders) ? userTrustedSenders : (typeof userTrustedSenders === "string" ? userTrustedSenders.split(/\n/) : []);
  document.getElementById("userTrustedSenders").value = senderList.join("\n");
}
load();
