import { expect, test } from "@playwright/test";

import { uniqueEmail } from "../support/test-users.js";
import { addVirtualAuthenticator } from "../support/webauthn.js";

test("unregistered user cannot login with a security key", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await page.getByLabel("Email").fill(uniqueEmail("missing"));
  await page.getByRole("button", { name: "Sign in with security key" }).click();
  await expect(page.getByTestId("status")).toHaveText("failed");

  const me = await page.evaluate(async () => {
    const response = await fetch("/me");
    return response.json();
  });
  expect(me).toMatchObject({ authenticated: false });
});

test("UV-required passkey registration fails when user verification is false", async ({
  page,
  context,
  request,
}) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: false,
  });
  try {
    await page.goto("/");
    await page.getByLabel("Email").fill(uniqueEmail("uv-failure"));
    await page.getByRole("button", { name: "Register passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("failed");

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
    expect(await authenticator.getCredentials()).toHaveLength(0);
  } finally {
    await authenticator.dispose();
  }
});

test("bogus assertion signature cannot create a session", async ({
  page,
  context,
  request,
}) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("bad-signature");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("registered");
    await page.getByRole("button", { name: "Logout" }).click();

    await authenticator.setBadSignature(true);
    await page.getByRole("button", { name: "Sign in with passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("failed");

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
  } finally {
    await authenticator.dispose();
  }
});

test("registration state replay is rejected", async ({ page, context }) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("registration-replay");
    await page.goto("/");
    const first = await page.evaluate(async (emailAddress) => {
      const helper = window.__webauthnE2E;
      const options = await helper.postJSON("/register/options", {
        email: emailAddress,
        displayName: emailAddress,
        mode: "platform",
      });
      const credential = await navigator.credentials.create({
        publicKey: helper.decodeCreationOptions(options),
      });
      if (credential == null) {
        throw new Error("null credential");
      }
      const body = {
        email: emailAddress,
        credential: helper.encodeRegistrationCredential(credential),
      };
      const ok = await helper.postJSON("/register/finish", body);
      return { body, ok };
    }, email);
    expect(first.ok).toMatchObject({ ok: true });

    const replay = await page.evaluate(async (body) => {
      const response = await fetch("/register/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    }, first.body);
    expect(replay.status).toBe(401);
  } finally {
    await authenticator.dispose();
  }
});

test("registration finish rejects mismatched ceremony email", async ({
  page,
  context,
}) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("registration-state");
    const otherEmail = uniqueEmail("registration-state-other");
    await page.goto("/");
    const result = await page.evaluate(
      async ({ emailAddress, mismatchedEmail }) => {
        const helper = window.__webauthnE2E;
        const options = await helper.postJSON("/register/options", {
          email: emailAddress,
          displayName: emailAddress,
          mode: "platform",
        });
        const credential = await navigator.credentials.create({
          publicKey: helper.decodeCreationOptions(options),
        });
        if (credential == null) {
          throw new Error("null credential");
        }
        const response = await fetch("/register/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: mismatchedEmail,
            credential: helper.encodeRegistrationCredential(credential),
          }),
        });
        return { status: response.status, body: await response.json() };
      },
      { emailAddress: email, mismatchedEmail: otherEmail },
    );

    expect(result.status).toBe(401);
    expect(result.body).toEqual({ ok: false, error: "Unauthorized" });

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
  } finally {
    await authenticator.dispose();
  }
});

test("authentication finish rejects mismatched username-first email", async ({
  page,
  context,
}) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "usb",
    residentKey: false,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("authentication-state");
    const otherEmail = uniqueEmail("authentication-state-other");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register security key" }).click();
    await expect(page.getByTestId("status")).toHaveText("registered");
    await page.getByRole("button", { name: "Logout" }).click();

    const result = await page.evaluate(
      async ({ emailAddress, mismatchedEmail }) => {
        const helper = window.__webauthnE2E;
        const options = await helper.postJSON("/login/options", {
          email: emailAddress,
          mode: "roaming",
        });
        const credential = await navigator.credentials.get({
          publicKey: helper.decodeRequestOptions(options),
        });
        if (credential == null) {
          throw new Error("null credential");
        }
        const response = await fetch("/login/finish", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            email: mismatchedEmail,
            credential: helper.encodeAuthenticationCredential(credential),
          }),
        });
        return { status: response.status, body: await response.json() };
      },
      { emailAddress: email, mismatchedEmail: otherEmail },
    );

    expect(result.status).toBe(401);
    expect(result.body).toEqual({ ok: false, error: "Unauthorized" });

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
  } finally {
    await authenticator.dispose();
  }
});

test("logout clears an authenticated session", async ({ page, context }) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("logout-session");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register passkey" }).click();
    await expect(page.getByTestId("current-user")).toHaveText(email);

    await page.getByRole("button", { name: "Logout" }).click();
    await expect(page.getByTestId("status")).toHaveText("logged out");
    await expect(page.getByTestId("current-user")).toHaveText(
      "unauthenticated",
    );

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
  } finally {
    await authenticator.dispose();
  }
});

test("finish handlers return generic errors for malformed JSON", async ({
  page,
}) => {
  await page.goto("/");

  for (const path of ["/register/finish", "/login/finish"]) {
    const result = await page.evaluate(async (endpoint) => {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: '{"credential":"raw-sensitive-material"',
      });
      return { status: response.status, body: await response.json() };
    }, path);

    expect(result.status).toBe(400);
    expect(result.body).toEqual({ ok: false, error: "Bad Request" });
    expect(JSON.stringify(result.body)).not.toContain("raw-sensitive-material");
  }
});
