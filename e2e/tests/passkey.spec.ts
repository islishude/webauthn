import { expect, test } from "@playwright/test";

import { uniqueEmail } from "../support/test-users.js";
import { addVirtualAuthenticator } from "../support/webauthn.js";

test("platform passkey registration and login", async ({ page, context }) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("platform");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("registered");
    await expect(page.getByTestId("current-user")).toHaveText(email);

    const credentials = await authenticator.getCredentials();
    expect(credentials).toHaveLength(1);

    await page.getByRole("button", { name: "Logout" }).click();
    await expect(page.getByTestId("current-user")).toHaveText(
      "unauthenticated",
    );
    await page.getByRole("button", { name: "Sign in with passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("authenticated");

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: true, user: { email } });
  } finally {
    await authenticator.dispose();
  }
});

test("authentication state replay is rejected", async ({ page, context }) => {
  const authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
    residentKey: true,
    userVerification: true,
    userVerified: true,
  });
  try {
    const email = uniqueEmail("auth-replay");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register passkey" }).click();
    await expect(page.getByTestId("status")).toHaveText("registered");
    await page.getByRole("button", { name: "Logout" }).click();

    const first = await page.evaluate(async () => {
      const helper = window.__webauthnE2E;
      const options = await helper.postJSON("/login/options", {
        mode: "platform",
      });
      const credential = await navigator.credentials.get({
        publicKey: helper.decodeRequestOptions(options),
      });
      const body = {
        email: "",
        credential: helper.encodeAuthenticationCredential(credential),
      };
      const ok = await helper.postJSON("/login/finish", body);
      return { body, ok };
    });
    expect(first.ok).toMatchObject({ ok: true });

    await page.getByRole("button", { name: "Logout" }).click();
    const replay = await page.evaluate(async (body) => {
      const response = await fetch("/login/finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    }, first.body);
    expect(replay.status).toBe(401);

    const me = await page.evaluate(async () => {
      const response = await fetch("/me");
      return response.json();
    });
    expect(me).toMatchObject({ authenticated: false });
  } finally {
    await authenticator.dispose();
  }
});
