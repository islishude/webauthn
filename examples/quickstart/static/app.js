const status = document.querySelector("#status");
const session = document.querySelector("#session");
const buttons = [...document.querySelectorAll("button")];
const supported =
  typeof PublicKeyCredential !== "undefined" &&
  typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function" &&
  typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function" &&
  typeof PublicKeyCredential.prototype.toJSON === "function";

async function post(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) throw new Error("Request failed. Start a new attempt.");
  return response.json();
}
async function refresh() {
  const response = await fetch("/me");
  if (!response.ok) throw new Error("Could not read session.");
  const state = await response.json();
  session.textContent = state.authenticated
    ? "Signed in to demo account"
    : "Signed out";
}
async function run(action, message) {
  buttons.forEach((button) => {
    button.disabled = true;
  });
  status.textContent = "Waiting for your authenticator…";
  try {
    await action();
    await refresh();
    status.textContent = message;
  } catch (error) {
    status.textContent =
      error instanceof Error ? error.message : "Please try again.";
  } finally {
    buttons.forEach((button) => {
      button.disabled = !supported;
    });
  }
}
document.querySelector("#register").addEventListener("click", () =>
  run(async () => {
    const options = await post("/register/options");
    const credential = await navigator.credentials.create({
      publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(options),
    });
    if (!credential) throw new Error("Registration cancelled.");
    await post("/register/finish", credential.toJSON());
  }, "Passkey registered. You can now sign in."),
);
document.querySelector("#login").addEventListener("click", () =>
  run(async () => {
    const options = await post("/login/options");
    const credential = await navigator.credentials.get({
      publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(options),
    });
    if (!credential) throw new Error("Sign-in cancelled.");
    await post("/login/finish", credential.toJSON());
  }, "Signed in."),
);
document
  .querySelector("#logout")
  .addEventListener("click", () => run(() => post("/logout"), "Signed out."));
buttons.forEach((button) => {
  button.disabled = !supported;
});
status.textContent = supported
  ? "Ready"
  : "This demo needs WebAuthn JSON conversion APIs. Please use a browser that supports them.";
try {
  await refresh();
} catch {
  status.textContent = "Could not connect to the local demo.";
}
