const emailInput = document.querySelector('input[aria-label="Email"]');
const status = document.querySelector('[data-testid="status"]');
const currentUser = document.querySelector('[data-testid="current-user"]');

document
  .querySelector("#register-passkey")
  .addEventListener("click", () => register("platform"));
document
  .querySelector("#register-security-key")
  .addEventListener("click", () => register("roaming"));
document
  .querySelector("#login-passkey")
  .addEventListener("click", () => login("platform"));
document
  .querySelector("#login-security-key")
  .addEventListener("click", () => login("roaming"));
document.querySelector("#logout").addEventListener("click", logout);

await refreshCurrentUser();

window.__webauthnE2E = {
  b64urlToBuffer,
  bufferToB64url,
  decodeCreationOptions,
  decodeRequestOptions,
  encodeRegistrationCredential,
  encodeAuthenticationCredential,
  postJSON,
};

async function register(mode) {
  try {
    setStatus("registering");
    const email = requireEmail();
    const options = await postJSON("/register/options", {
      email,
      displayName: email,
      mode,
    });
    const credential = await navigator.credentials.create({
      publicKey: decodeCreationOptions(options),
    });
    const result = await postJSON("/register/finish", {
      email,
      credential: encodeRegistrationCredential(credential),
    });
    setStatus(result.ok ? "registered" : "failed");
    await refreshCurrentUser();
  } catch {
    setStatus("failed");
    await refreshCurrentUser();
  }
}

async function login(mode) {
  try {
    setStatus("authenticating");
    const email = emailInput.value.trim();
    const options = await postJSON("/login/options", { email, mode });
    const credential = await navigator.credentials.get({
      publicKey: decodeRequestOptions(options),
    });
    const result = await postJSON("/login/finish", {
      email,
      credential: encodeAuthenticationCredential(credential),
    });
    setStatus(result.ok ? "authenticated" : "failed");
    await refreshCurrentUser();
  } catch {
    setStatus("failed");
    await refreshCurrentUser();
  }
}

async function logout() {
  await postJSON("/logout", {});
  setStatus("logged out");
  await refreshCurrentUser();
}

async function refreshCurrentUser() {
  const response = await fetch("/me");
  const body = await response.json();
  currentUser.textContent = body.authenticated
    ? body.user.email
    : "unauthenticated";
}

function requireEmail() {
  const email = emailInput.value.trim();
  if (!email) {
    throw new Error("email required");
  }
  return email;
}

function setStatus(value) {
  status.textContent = value;
}

async function postJSON(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || "request failed");
  }
  return payload;
}

function decodeCreationOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: b64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map(
      (credential) => ({
        ...credential,
        id: b64urlToBuffer(credential.id),
      }),
    ),
  };
}

function decodeRequestOptions(options) {
  return {
    ...options,
    challenge: b64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: b64urlToBuffer(credential.id),
    })),
  };
}

function encodeRegistrationCredential(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      attestationObject: bufferToB64url(response.attestationObject),
      authenticatorData: optionalBufferToB64url(
        response.getAuthenticatorData?.(),
      ),
      publicKey: optionalBufferToB64url(response.getPublicKey?.()),
      publicKeyAlgorithm: response.getPublicKeyAlgorithm?.() || 0,
      transports: response.getTransports?.() || [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function encodeAuthenticationCredential(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToB64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    response: {
      clientDataJSON: bufferToB64url(response.clientDataJSON),
      authenticatorData: bufferToB64url(response.authenticatorData),
      signature: bufferToB64url(response.signature),
      userHandle: optionalBufferToB64url(response.userHandle),
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function optionalBufferToB64url(value) {
  return value ? bufferToB64url(value) : undefined;
}

function b64urlToBuffer(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const bytes = Uint8Array.from(atob(padded), (ch) => ch.charCodeAt(0));
  return bytes.buffer;
}

function bufferToB64url(value) {
  const bytes = new Uint8Array(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}
