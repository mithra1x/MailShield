chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type !== "PMD_BADGE_UPDATE") return;
  const level = msg.result?.level || "";
  const text = level === "High" ? "H" : level === "Medium" ? "M" : level === "Low" ? "L" : "";
  const color = level === "High" ? "#c00" : level === "Medium" ? "#b80" : "#2e7d32";
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
});
