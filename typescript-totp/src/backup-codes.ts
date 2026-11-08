export interface BackupCodeOptions {
  readonly count?: number;
  readonly bytesPerCode?: number;
  readonly groupSize?: number;
}

export type RandomBytes = (length: number) => Uint8Array;

export function formatBackupCode(
  randomBytes: Uint8Array,
  groupSize = 4,
): string {
  if (randomBytes.length === 0)
    throw new RangeError("backup-code entropy must not be empty");
  if (!Number.isSafeInteger(groupSize) || groupSize <= 0) {
    throw new RangeError("backup-code groupSize must be a positive integer");
  }
  const encoded = Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  )
    .join("")
    .toUpperCase();
  const groups: string[] = [];
  for (let offset = 0; offset < encoded.length; offset += groupSize) {
    groups.push(encoded.slice(offset, offset + groupSize));
  }
  return groups.join("-");
}

export function createBackupCodes(
  randomBytes: RandomBytes,
  options: BackupCodeOptions = {},
): string[] {
  const count = options.count ?? 10;
  const bytesPerCode = options.bytesPerCode ?? 4;
  const groupSize = options.groupSize ?? 4;
  if (!Number.isSafeInteger(count) || count <= 0) {
    throw new RangeError("backup-code count must be a positive integer");
  }
  if (!Number.isSafeInteger(bytesPerCode) || bytesPerCode <= 0) {
    throw new RangeError("backup-code bytesPerCode must be a positive integer");
  }
  return Array.from({ length: count }, () => {
    const entropy = randomBytes(bytesPerCode);
    if (entropy.length !== bytesPerCode) {
      throw new Error("randomBytes returned an unexpected number of bytes");
    }
    return formatBackupCode(entropy, groupSize);
  });
}
