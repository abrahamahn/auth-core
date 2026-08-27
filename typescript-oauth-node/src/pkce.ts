import { createHash, randomBytes } from 'node:crypto';

export interface PkcePair {
  readonly verifier: string;
  readonly challenge: string;
  readonly method: 'S256';
}

/** Generate an RFC 7636 S256 verifier/challenge pair. */
export function createPkcePair(random: (size: number) => Buffer = randomBytes): PkcePair {
  const verifier = random(32).toString('base64url');
  if (verifier.length < 43 || verifier.length > 128) {
    throw new Error('PKCE verifier source must produce between 43 and 128 characters');
  }
  return {
    verifier,
    challenge: createHash('sha256').update(verifier, 'ascii').digest('base64url'),
    method: 'S256',
  };
}
