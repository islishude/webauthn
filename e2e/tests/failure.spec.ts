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
