export {};

declare global {
  interface Window {
    __webauthnE2E: {
      postJSON(path: string, body: unknown): Promise<unknown>;
      decodeCreationOptions(
        options: unknown,
      ): PublicKeyCredentialCreationOptions;
      decodeRequestOptions(options: unknown): PublicKeyCredentialRequestOptions;
      encodeRegistrationCredential(credential: Credential): unknown;
      encodeAuthenticationCredential(credential: Credential): unknown;
    };
  }
}
