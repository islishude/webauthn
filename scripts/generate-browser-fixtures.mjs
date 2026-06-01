#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const outputPath = path.join(
  repoRoot,
  "testdata",
  "browser",
  "virtual-authenticator",
  "fixtures.json",
);
const rpID = "webauthn.test";
const origin = `https://${rpID}`;
const { chromium, playwrightPackage } = await loadPlaywright();

async function loadPlaywright() {
  if (process.env.PLAYWRIGHT_MODULE_DIR) {
    const packageRoot = path.join(
      process.env.PLAYWRIGHT_MODULE_DIR,
      "playwright",
    );
    const playwright = await import(
      pathToFileURL(path.join(packageRoot, "index.mjs")).href
    );
    const packageJSON = JSON.parse(
      await fs.readFile(path.join(packageRoot, "package.json"), "utf8"),
    );

    return { chromium: playwright.chromium, playwrightPackage: packageJSON };
  }

  const playwright = await import("playwright");
  const packageURL = import.meta.resolve("playwright/package.json");
  const packageJSON = JSON.parse(
    await fs.readFile(fileURLToPath(packageURL), "utf8"),
  );

  return { chromium: playwright.chromium, playwrightPackage: packageJSON };
}

function bytesToBase64URL(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function textToBase64URL(text) {
  return bytesToBase64URL(Buffer.from(text, "utf8"));
}

function chromeExecutablePath() {
  if (process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE) {
    return process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE;
  }
  if (process.platform === "darwin") {
    return "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
  }

  return "";
}

async function launchBrowser() {
  const executablePath = chromeExecutablePath();
  const options = { headless: true };
  if (executablePath) {
    try {
      await fs.access(executablePath);
      options.executablePath = executablePath;
    } catch {
      // Fall back to Playwright's managed browser when available.
    }
  }

  return chromium.launch(options);
}

async function scenario(browser, definition) {
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  await context.route(`${origin}/**`, (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: "<!doctype html><title>WebAuthn fixture</title>",
    }),
  );
  const page = await context.newPage();
  await page.goto(origin);

  const client = await context.newCDPSession(page);
  await client.send("WebAuthn.enable");
  const { authenticatorId } = await client.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: definition.authenticator,
    },
  );

  try {
    const user = {
      id: textToBase64URL(definition.userID),
      name: `${definition.userID}@example.test`,
      displayName: definition.displayName,
    };
    const registrationChallenge = textToBase64URL(
      `${definition.name}:registration:challenge`,
    );
    const authenticationChallenge = textToBase64URL(
      `${definition.name}:authentication:challenge`,
    );

    const registration = await page.evaluate(
      async ({ challenge, rpID, user, authenticatorSelection }) => {
        function base64URLToArrayBuffer(value) {
          const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
          const padded = normalized.padEnd(
            Math.ceil(normalized.length / 4) * 4,
            "=",
          );
          const bytes = Uint8Array.from(atob(padded), (char) =>
            char.charCodeAt(0),
          );
          return bytes.buffer;
        }

        function arrayBufferToBase64URL(value) {
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

        const credential = await navigator.credentials.create({
          publicKey: {
            rp: { id: rpID, name: "WebAuthn Test RP" },
            user: {
              id: base64URLToArrayBuffer(user.id),
              name: user.name,
              displayName: user.displayName,
            },
            challenge: base64URLToArrayBuffer(challenge),
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            timeout: 60000,
            authenticatorSelection,
            attestation: "none",
          },
        });

        return {
          type: credential.type,
          id: credential.id,
          rawID: arrayBufferToBase64URL(credential.rawId),
          clientDataJSON: arrayBufferToBase64URL(
            credential.response.clientDataJSON,
          ),
          attestationObject: arrayBufferToBase64URL(
            credential.response.attestationObject,
          ),
          transports:
            typeof credential.response.getTransports === "function"
              ? credential.response.getTransports()
              : [],
          clientExtensionResults: credential.getClientExtensionResults(),
        };
      },
      {
        challenge: registrationChallenge,
        rpID,
        user,
        authenticatorSelection: definition.authenticatorSelection,
      },
    );

    const authentication = await page.evaluate(
      async ({ challenge, rpID, allowCredential, userVerification }) => {
        function base64URLToArrayBuffer(value) {
          const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
          const padded = normalized.padEnd(
            Math.ceil(normalized.length / 4) * 4,
            "=",
          );
          const bytes = Uint8Array.from(atob(padded), (char) =>
            char.charCodeAt(0),
          );
          return bytes.buffer;
        }

        function arrayBufferToBase64URL(value) {
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

        const publicKey = {
          challenge: base64URLToArrayBuffer(challenge),
          rpId: rpID,
          timeout: 60000,
          userVerification,
        };
        if (allowCredential) {
          publicKey.allowCredentials = [
            {
              type: "public-key",
              id: base64URLToArrayBuffer(allowCredential.id),
              transports: allowCredential.transports,
            },
          ];
        }

        const assertion = await navigator.credentials.get({ publicKey });
        return {
          type: assertion.type,
          id: assertion.id,
          rawID: arrayBufferToBase64URL(assertion.rawId),
          clientDataJSON: arrayBufferToBase64URL(
            assertion.response.clientDataJSON,
          ),
          authenticatorData: arrayBufferToBase64URL(
            assertion.response.authenticatorData,
          ),
          signature: arrayBufferToBase64URL(assertion.response.signature),
          userHandle: assertion.response.userHandle
            ? arrayBufferToBase64URL(assertion.response.userHandle)
            : "",
          clientExtensionResults: assertion.getClientExtensionResults(),
        };
      },
      {
        challenge: authenticationChallenge,
        rpID,
        allowCredential: definition.allowCredentials
          ? {
              id: registration.rawID,
              transports: registration.transports,
            }
          : null,
        userVerification: definition.authenticationUserVerification,
      },
    );

    return {
      name: definition.name,
      description: definition.description,
      rpID,
      origin,
      flow: definition.flow,
      authenticator: {
        protocol: definition.authenticator.protocol,
        transport: definition.authenticator.transport,
        hasResidentKey: definition.authenticator.hasResidentKey,
        hasUserVerification: definition.authenticator.hasUserVerification,
        isUserVerified: definition.authenticator.isUserVerified,
      },
      user,
      registration: {
        challenge: registrationChallenge,
        userVerification: definition.registrationUserVerification,
        authenticatorSelection: definition.authenticatorSelection,
        ...registration,
      },
      authentication: {
        challenge: authenticationChallenge,
        userVerification: definition.authenticationUserVerification,
        allowCredentials: definition.allowCredentials,
        ...authentication,
      },
    };
  } finally {
    await client.send("WebAuthn.removeVirtualAuthenticator", {
      authenticatorId,
    });
    await context.close();
  }
}

async function main() {
  const browser = await launchBrowser();
  try {
    const fixtures = [];
    for (const definition of [
      {
        name: "platform-discoverable-uv-required",
        description:
          "Platform-style CTAP2 authenticator with resident key and UV-required discoverable authentication.",
        flow: "discoverable",
        userID: "platform-user-1",
        displayName: "Platform User",
        allowCredentials: false,
        registrationUserVerification: "required",
        authenticationUserVerification: "required",
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        authenticator: {
          protocol: "ctap2",
          transport: "internal",
          hasResidentKey: true,
          hasUserVerification: true,
          isUserVerified: true,
          automaticPresenceSimulation: true,
        },
      },
      {
        name: "roaming-allow-credentials-username-first",
        description:
          "Roaming-style CTAP2 authenticator verified through an allowCredentials username-first flow.",
        flow: "username-first",
        userID: "roaming-user-1",
        displayName: "Roaming User",
        allowCredentials: true,
        registrationUserVerification: "preferred",
        authenticationUserVerification: "preferred",
        authenticatorSelection: {
          authenticatorAttachment: "cross-platform",
          residentKey: "discouraged",
          requireResidentKey: false,
          userVerification: "preferred",
        },
        authenticator: {
          protocol: "ctap2",
          transport: "usb",
          hasResidentKey: false,
          hasUserVerification: false,
          isUserVerified: false,
          automaticPresenceSimulation: true,
        },
      },
    ]) {
      fixtures.push(await scenario(browser, definition));
    }

    const output = {
      metadata: {
        source:
          "Generated specifically for github.com/islishude/webauthn by scripts/generate-browser-fixtures.mjs.",
        generatedAt: "2026-06-01",
        generator: `Playwright ${playwrightPackage.version} with Chrome DevTools WebAuthn virtual authenticators`,
        browserVersion: browser.version(),
        normativeContext:
          "W3C Web Authentication Level 2 relying-party registration and authentication operations.",
        sensitivity:
          "test-only synthetic credentials; no production account, credential, authenticator, or private-key material is included intentionally.",
        externalConformanceData: "none",
      },
      fixtures,
    };

    await fs.mkdir(path.dirname(outputPath), { recursive: true });
    await fs.writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`);
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
