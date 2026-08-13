const maxPublicConfigurationMessageLength = 320;

/** A startup configuration failure whose fixed remediation is safe to log. */
export class HubConfigurationError extends Error {
  readonly publicMessage: string;

  constructor(publicMessage: string) {
    super(publicMessage);
    this.name = "HubConfigurationError";
    this.publicMessage = publicMessage.slice(
      0,
      maxPublicConfigurationMessageLength,
    );
  }
}

export function isHubConfigurationError(
  error: unknown,
): error is HubConfigurationError {
  return error instanceof HubConfigurationError;
}
