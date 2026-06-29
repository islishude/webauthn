import type { BrowserContext } from "@playwright/test";

type CDPSession = Awaited<ReturnType<BrowserContext["newCDPSession"]>>;

type AuthenticatorOptions = {
  transport: "internal" | "usb";
  residentKey?: boolean;
  userVerification?: boolean;
  userVerified?: boolean;
};

export type VirtualAuthenticator = {
  getCredentials(): Promise<unknown[]>;
  setUserVerified(value: boolean): Promise<void>;
  setBadSignature(value: boolean): Promise<void>;
  dispose(): Promise<void>;
};

export async function addVirtualAuthenticator(
  context: BrowserContext,
  options: AuthenticatorOptions,
): Promise<VirtualAuthenticator> {
  const page = context.pages()[0] ?? (await context.newPage());
  const cdp: CDPSession = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send(
    "WebAuthn.addVirtualAuthenticator",
    {
      options: {
        protocol: "ctap2",
        ctap2Version: "ctap2_1",
        transport: options.transport,
        hasResidentKey: options.residentKey ?? true,
        hasUserVerification: options.userVerification ?? true,
        isUserVerified: options.userVerified ?? true,
        automaticPresenceSimulation: true,
      },
    },
  );

  return {
    async getCredentials() {
      const result = await cdp.send("WebAuthn.getCredentials", {
        authenticatorId,
      });
      return result.credentials ?? [];
    },
    async setUserVerified(value: boolean) {
      await cdp.send("WebAuthn.setUserVerified", {
        authenticatorId,
        isUserVerified: value,
      });
    },
    async setBadSignature(value: boolean) {
      await cdp.send("WebAuthn.setResponseOverrideBits", {
        authenticatorId,
        isBogusSignature: value,
      });
    },
    async dispose() {
      await cdp.send("WebAuthn.removeVirtualAuthenticator", {
        authenticatorId,
      });
      await cdp.detach();
    },
  };
}
