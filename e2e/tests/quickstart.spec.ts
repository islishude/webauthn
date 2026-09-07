import { expect, test } from "@playwright/test";
import { addVirtualAuthenticator } from "../support/webauthn.js";

test("public quickstart registers, authenticates and logs out using native JSON", async ({
  page,
  context,
}) => {
  await using authenticator = await addVirtualAuthenticator(context, {
    transport: "internal",
  });
  await page.goto("/");
  await expect(page.locator("#status")).toHaveText("Ready");
  await page.getByRole("button", { name: "Register passkey" }).click();
  await expect(page.locator("#status")).toHaveText(
    "Passkey registered. You can now sign in.",
  );
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.locator("#session")).toHaveText(
    "Signed in to demo account",
  );
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.locator("#session")).toHaveText("Signed out");
  expect(await authenticator.getCredentials()).toHaveLength(1);
});

test("public quickstart explains missing JSON API support", async ({
  page,
}) => {
  await page.addInitScript(() => {
    Object.defineProperty(PublicKeyCredential, "parseCreationOptionsFromJSON", {
      value: undefined,
    });
  });
  await page.goto("/");
  await expect(page.locator("#status")).toContainText(
    "needs WebAuthn JSON conversion APIs",
  );
  await expect(
    page.getByRole("button", { name: "Register passkey" }),
  ).toBeDisabled();
});
