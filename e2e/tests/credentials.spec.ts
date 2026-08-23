import { expect, test, type Page } from "@playwright/test";

import { uniqueEmail } from "../support/test-users.js";

const baseURL = "https://localhost:8443";
const rpID = "localhost";

test("Playwright credentials can capture, delete, and reseed a passkey", async ({
  page,
  context,
}) => {
  await context.credentials.install();

  const email = uniqueEmail("credentials-lifecycle");
  await registerPasskey(page, email);

  const credentials = await context.credentials.get({ rpId: rpID });
  expect(credentials).toHaveLength(1);
  const credential = credentials[0]!;
  expect(credential.rpId).toBe(rpID);
  expect(credential.id).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(credential.userHandle).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(credential.privateKey).toMatch(/^[A-Za-z0-9_-]+$/);
  expect(credential.publicKey).toMatch(/^[A-Za-z0-9_-]+$/);
  await expect
    .poll(async () => context.credentials.get({ id: credential.id }))
    .toHaveLength(1);

  await logout(page);
  await context.credentials.delete(credential.id);
  expect(await context.credentials.get({ id: credential.id })).toEqual([]);

  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(page.getByTestId("status")).toHaveText("failed");

  await context.credentials.create(credential.rpId, {
    id: credential.id,
    userHandle: credential.userHandle,
    privateKey: credential.privateKey,
    publicKey: credential.publicKey,
  });
  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(page.getByTestId("status")).toHaveText("authenticated");
  await expect(page.getByTestId("current-user")).toHaveText(email);
});

test("credential-inclusive storage state restores a passkey in a new context", async ({
  browser,
}) => {
  const email = uniqueEmail("credentials-storage-state");
  const storageState = await (async () => {
    await using context = await browser.newContext({
      baseURL,
      ignoreHTTPSErrors: true,
    });
    await context.credentials.install();
    const page = await context.newPage();
    await registerPasskey(page, email);
    await logout(page);
    return context.storageState({ credentials: true });
  })();

  expect(
    (storageState as typeof storageState & { credentials: unknown[] })
      .credentials,
  ).toHaveLength(1);
  await using restored = await browser.newContext({
    baseURL,
    ignoreHTTPSErrors: true,
    storageState,
  });
  expect(await restored.credentials.get({ rpId: rpID })).toHaveLength(1);
  const page = await restored.newPage();
  await page.goto("/");
  await page.getByRole("button", { name: "Sign in with passkey" }).click();
  await expect(page.getByTestId("status")).toHaveText("authenticated");
  await expect(page.getByTestId("current-user")).toHaveText(email);
});

async function registerPasskey(page: Page, email: string): Promise<void> {
  await page.goto("/");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: "Register passkey" }).click();
  await expect(page.getByTestId("status")).toHaveText("registered");
  await expect(page.getByTestId("current-user")).toHaveText(email);
}

async function logout(page: Page): Promise<void> {
  await page.getByRole("button", { name: "Logout" }).click();
  await expect(page.getByTestId("status")).toHaveText("logged out");
  await expect(page.getByTestId("current-user")).toHaveText("unauthenticated");
}
