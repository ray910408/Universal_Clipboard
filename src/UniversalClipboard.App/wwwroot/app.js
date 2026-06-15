"use strict";

const CONTRACT = Object.freeze(
/* app-contract:start */
{
  "pollIntervalMs": 1000,
  "maxItems": 3,
  "bootstrapEvent": "pageshow",
  "clearOn": ["hidden", "pagehide", "unauthorized", "pairing", "pageshow"],
  "transitions": {
    "hidden": ["stopPolling", "clearClipboardDom", "resetIdentity"],
    "pagehide": ["stopPolling", "clearClipboardDom", "resetIdentity"],
    "unauthorized": ["stopPolling", "clearClipboardDom", "resetIdentity", "showPairing"],
    "pairing": ["stopPolling", "clearClipboardDom", "resetIdentity", "showLoading"],
    "pageshow": ["stopPolling", "clearClipboardDom", "resetIdentity", "showLoading", "pollFull"],
    "error": ["clearClipboardDom", "resetIdentity", "showError"]
  },
  "pairing": {
    "fragmentKey": "code",
    "cleanPath": "/pair",
    "codePattern": "^[A-Za-z0-9_-]{32}$",
    "cleanupBeforePost": true,
    "clearVariableFinally": true
  },
  "copy": {
    "confirmed": "Copied",
    "fallback": "Copy requested - verify, or long-press and choose Copy"
  },
  "incoming": {
    "endpoint": "/clip-api/incoming-text",
    "storageKey": "uc.permission",
    "readPermissions": ["read", "readWrite"],
    "writePermissions": ["write", "readWrite"],
    "disabled": "Re-pair from Windows with Write enabled.",
    "queued": "Pending in Windows tray.",
    "empty": "Enter text before sending.",
    "failed": "Unable to send. Check pairing and try again."
  },
  "session": {
    "storageKey": "uc.sessionProof",
    "headerName": "X-Clip-Session"
  }
}
/* app-contract:end */
);

const stateSections = new Map(
  Array.from(document.querySelectorAll("[data-state]"))
    .map((element) => [element.dataset.state, element]));
const itemsList = document.querySelector("#items-list");
const fallbackText = document.querySelector("#copy-fallback");
const copyStatus = document.querySelector("#copy-status");
const pairingMessage = document.querySelector("#pairing-message");
const errorMessage = document.querySelector("#error-message");
const incomingText = document.querySelector("#incoming-text");
const incomingSend = document.querySelector("#incoming-send");
const incomingStatus = document.querySelector("#incoming-status");
const incomingPermission = document.querySelector("#incoming-permission");

let instanceId = null;
let version = null;
let pollTimer = null;
let activeRequest = null;
let pairingInProgress = false;
let refreshInProgress = false;

function setState(name) {
  for (const [state, element] of stateSections) {
    element.hidden = state !== name;
  }
}

function clearClipboardDom() {
  itemsList.replaceChildren();
  fallbackText.value = "";
  copyStatus.textContent = "";
}

function stopPolling() {
  if (pollTimer !== null) {
    window.clearTimeout(pollTimer);
    pollTimer = null;
  }

  if (activeRequest !== null) {
    activeRequest.abort();
    activeRequest = null;
  }
}

function resetFeed() {
  stopPolling();
  clearClipboardDom();
  sessionStorage.removeItem(CONTRACT.session.storageKey);
  sessionStorage.removeItem(CONTRACT.incoming.storageKey);
  updateIncomingPermission(null);
  instanceId = null;
  version = null;
}

function applyLifecycleTransition(name) {
  const actions = CONTRACT.transitions[name];
  let pollFull = false;

  for (const action of actions) {
    switch (action) {
      case "stopPolling":
        stopPolling();
        break;
      case "clearClipboardDom":
        clearClipboardDom();
        break;
      case "resetIdentity":
        instanceId = null;
        version = null;
        break;
      case "showPairing":
        setState("pairing");
        break;
      case "showLoading":
        setState("loading");
        break;
      case "showError":
        setState("error");
        break;
      case "pollFull":
        pollFull = true;
        break;
      default:
        throw new Error("unknown lifecycle action");
    }
  }

  return pollFull;
}

function schedulePoll() {
  if (document.visibilityState !== "visible" || pollTimer !== null) {
    return;
  }

  pollTimer = window.setTimeout(() => {
    pollTimer = null;
    void pollClips(false);
  }, CONTRACT.pollIntervalMs);
}

function sessionHeaders() {
  const sessionProof = sessionStorage.getItem(CONTRACT.session.storageKey);
  return sessionProof === null
    ? {}
    : { [CONTRACT.session.headerName]: sessionProof };
}

function canSendToWindows(permission) {
  return CONTRACT.incoming.writePermissions.includes(permission);
}

function canReadFromWindows(permission) {
  return permission === null || CONTRACT.incoming.readPermissions.includes(permission);
}

function updateIncomingPermission(permission) {
  const allowed = canSendToWindows(permission);
  incomingText.disabled = !allowed;
  incomingSend.disabled = !allowed;
  incomingPermission.textContent = allowed ? "Write enabled" : "Read only";
  if (!allowed) {
    incomingStatus.textContent = CONTRACT.incoming.disabled;
  } else if (incomingStatus.textContent === CONTRACT.incoming.disabled) {
    incomingStatus.textContent = "";
  }
}

function clearStoredSession() {
  sessionStorage.removeItem(CONTRACT.session.storageKey);
  sessionStorage.removeItem(CONTRACT.incoming.storageKey);
  updateIncomingPermission(null);
}

function relativeTime(value) {
  const copiedAt = Date.parse(value);
  if (!Number.isFinite(copiedAt)) {
    return "Recently";
  }

  const seconds = Math.max(0, Math.floor((Date.now() - copiedAt) / 1000));
  if (seconds < 10) {
    return "Just now";
  }

  if (seconds < 60) {
    return `${seconds} seconds ago`;
  }

  const minutes = Math.floor(seconds / 60);
  return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
}

function selectFallbackText(text) {
  fallbackText.value = text;
  fallbackText.focus({ preventScroll: true });
  fallbackText.select();
  fallbackText.setSelectionRange(0, fallbackText.value.length);
}

async function copySelectedText(text, statusElement) {
  selectFallbackText(text);
  if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
    try {
      await navigator.clipboard.writeText(text);
      statusElement.textContent = CONTRACT.copy.confirmed;
      return;
    } catch {
      selectFallbackText(text);
    }
  }

  try {
    document.execCommand("copy");
  } catch {
    // Selection remains visible for long-press copy.
  }

  statusElement.textContent = CONTRACT.copy.fallback;
}

function renderItems(items) {
  itemsList.replaceChildren();
  const newest = Array.isArray(items) ? items.slice(0, CONTRACT.maxItems) : [];

  for (const item of newest) {
    const card = document.createElement("article");
    card.className = "clip-card";

    const text = document.createElement("p");
    text.className = "clip-text";
    text.textContent = typeof item.text === "string" ? item.text : "";

    const meta = document.createElement("div");
    meta.className = "clip-meta";

    const time = document.createElement("span");
    time.className = "clip-time";
    time.textContent = relativeTime(item.copiedAt);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "copy-button";
    button.textContent = "Copy to iPhone";
    button.addEventListener("click", () => {
      copyStatus.textContent = "";
      void copySelectedText(text.textContent, copyStatus);
    });

    meta.append(time, button);
    card.append(text, meta);
    itemsList.append(card);
  }

  setState(newest.length === 0 ? "empty" : "items");
}

function buildClipsUrl() {
  if (instanceId === null || version === null) {
    return "/clip-api/clips";
  }

  const query = new URLSearchParams({
    instance: instanceId,
    since: String(version)
  });
  return `/clip-api/clips?${query.toString()}`;
}

async function pollClips(forceFull) {
  if (document.visibilityState !== "visible") {
    return;
  }

  if (!canReadFromWindows(sessionStorage.getItem(CONTRACT.incoming.storageKey))) {
    instanceId = null;
    version = null;
    renderItems([]);
    return;
  }

  if (forceFull) {
    instanceId = null;
    version = null;
  }

  const requestController = new AbortController();
  const headers = sessionHeaders();
  activeRequest = requestController;
  try {
    const response = await fetch(buildClipsUrl(), {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers,
      signal: requestController.signal
    });

    if (response.status === 401) {
      clearStoredSession();
      applyLifecycleTransition("unauthorized");
      pairingMessage.textContent =
        "Pairing expired or was revoked. Generate a new code on Windows.";
      return;
    }

    if (response.status === 403) {
      instanceId = null;
      version = null;
      renderItems([]);
      return;
    }

    if (response.status === 204) {
      schedulePoll();
      return;
    }

    if (!response.ok) {
      throw new Error("refresh failed");
    }

    const snapshot = await response.json();
    instanceId = snapshot.instanceId;
    version = snapshot.version;
    renderItems(snapshot.items);
    schedulePoll();
  } catch (error) {
    if (error && error.name === "AbortError") {
      return;
    }

    applyLifecycleTransition("error");
    errorMessage.textContent =
      "Check that both devices are on the same private Wi-Fi network.";
    schedulePoll();
  } finally {
    if (activeRequest === requestController) {
      activeRequest = null;
    }
  }
}

function detectBrowserName() {
  const userAgent = navigator.userAgent;
  if (userAgent.includes("CriOS")) {
    return "Chrome";
  }

  if (userAgent.includes("FxiOS")) {
    return "Firefox";
  }

  if (userAgent.includes("EdgiOS")) {
    return "Edge";
  }

  if (userAgent.includes("Safari")) {
    return "Safari";
  }

  return "Browser";
}

function detectDeviceName() {
  const userAgent = navigator.userAgent;
  if (userAgent.includes("iPad")) {
    return "iPad";
  }

  if (userAgent.includes("iPhone")) {
    return "iPhone";
  }

  return "Mobile device";
}

async function postPairingCode(pairingCode) {
  const deviceName = detectDeviceName();
  const browserName = detectBrowserName();
  return fetch("/clip-api/pair/exchange", {
    method: "POST",
    credentials: "same-origin",
    cache: "no-store",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      code: pairingCode,
      label: `${deviceName} ${browserName}`,
      deviceName,
      browserName
    })
  });
}

async function sendIncomingText() {
  const text = incomingText.value;
  if (text.length === 0) {
    incomingStatus.textContent = CONTRACT.incoming.empty;
    return;
  }

  incomingSend.disabled = true;
  incomingStatus.textContent = "";
  try {
    const response = await fetch(CONTRACT.incoming.endpoint, {
      method: "POST",
      credentials: "same-origin",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
        ...sessionHeaders()
      },
      body: JSON.stringify({ text })
    });

    if (response.status === 401) {
      clearStoredSession();
      applyLifecycleTransition("unauthorized");
      pairingMessage.textContent =
        "Pairing expired or was revoked. Generate a new code on Windows.";
      return;
    }

    if (response.status === 403) {
      sessionStorage.setItem(CONTRACT.incoming.storageKey, "read");
      updateIncomingPermission("read");
      return;
    }

    if (!response.ok) {
      throw new Error("incoming send failed");
    }

    incomingText.value = "";
    incomingStatus.textContent = CONTRACT.incoming.queued;
  } catch {
    incomingStatus.textContent = CONTRACT.incoming.failed;
  } finally {
    incomingSend.disabled = !canSendToWindows(
      sessionStorage.getItem(CONTRACT.incoming.storageKey));
  }
}

async function exchangePairingFragment() {
  let pairingCode = "";
  pairingInProgress = true;
  applyLifecycleTransition("pairing");

  try {
    const parameters = new URLSearchParams(window.location.hash.slice(1));
    if (parameters.size !== 1 || !parameters.has(CONTRACT.pairing.fragmentKey)) {
      throw new Error("malformed pairing fragment");
    }

    pairingCode = parameters.get(CONTRACT.pairing.fragmentKey) || "";
    const pattern = new RegExp(CONTRACT.pairing.codePattern);
    if (!pattern.test(pairingCode)) {
      throw new Error("malformed pairing code");
    }

    history.replaceState(null, "", CONTRACT.pairing.cleanPath);
    const response = await postPairingCode(pairingCode);
    if (!response.ok) {
      throw new Error("pairing failed");
    }

    const pairing = await response.json();
    if (typeof pairing.sessionProof !== "string" || pairing.sessionProof.length === 0) {
      throw new Error("pairing proof missing");
    }

    sessionStorage.setItem(CONTRACT.session.storageKey, pairing.sessionProof);
    sessionStorage.setItem(CONTRACT.incoming.storageKey, pairing.permission || "read");
    updateIncomingPermission(pairing.permission || "read");
    await pollClips(true);
  } catch {
    clearStoredSession();
    applyLifecycleTransition("unauthorized");
    pairingMessage.textContent =
      "Pairing failed. Generate a new code on Windows and scan it again.";
  } finally {
    pairingCode = "";
    pairingInProgress = false;
  }
}

async function refreshAfterPageShow() {
  if (pairingInProgress ||
      refreshInProgress ||
      document.visibilityState !== "visible") {
    return;
  }

  refreshInProgress = true;
  try {
    updateIncomingPermission(sessionStorage.getItem(CONTRACT.incoming.storageKey));
    if (applyLifecycleTransition("pageshow")) {
      await pollClips(true);
    }
  } finally {
    refreshInProgress = false;
  }
}

async function refreshVisiblePage() {
  if (window.location.pathname === "/pair" && window.location.hash.length > 1) {
    await exchangePairingFragment();
    return;
  }

  await refreshAfterPageShow();
}

document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "hidden") {
    applyLifecycleTransition("hidden");
    return;
  }

  void refreshVisiblePage();
});

window.addEventListener("pagehide", () => {
  applyLifecycleTransition("pagehide");
});

window.addEventListener(CONTRACT.bootstrapEvent, () => {
  void refreshVisiblePage();
});

incomingSend.addEventListener("click", () => {
  void sendIncomingText();
});

updateIncomingPermission(sessionStorage.getItem(CONTRACT.incoming.storageKey));
