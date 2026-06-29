import { expect, test } from "@playwright/test";

import { uniqueEmail } from "../support/test-users.js";
import { addVirtualAuthenticator } from "../support/webauthn.js";

test("roaming security key registration and username-first login", async ({
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
    const email = uniqueEmail("roaming");
    await page.goto("/");
    await page.getByLabel("Email").fill(email);
    await page.getByRole("button", { name: "Register security key" }).click();
    await expect(page.getByTestId("status")).toHaveText("registered");

    await page.getByRole("button", { name: "Logout" }).click();
    await page.getByLabel("Email").fill(email);
    await page
      .getByRole("button", { name: "Sign in with security key" })
      .click();
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
