/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import crypto from 'crypto';

// Server-side constant secret for JWT signing, fallback to dynamic seed if env is missing
const SECRET_KEY = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Base64URL encode buffer or string
 */
function base64urlEncode(input: Buffer | string): string {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Base64URL decode string
 */
function base64urlDecode(input: string): string {
  let str = input.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) {
    str += '=';
  }
  return Buffer.from(str, 'base64').toString('utf8');
}

/**
 * Generates a PBKDF2 password hash and salt.
 * Standard secure practice (OWASP recommended hashing)
 */
export function hashPassword(password: string): { hash: string; salt: string } {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

/**
 * Verifies a password against an existing salt and PBKDF2 hash.
 */
export function verifyPassword(password: string, salt: string, existingHash: string): boolean {
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(existingHash, 'hex'));
}

/**
 * Custom sign JWT function
 */
export function signJwt(payload: Record<string, any>, customSecret: string = SECRET_KEY): string {
  const header = {
    alg: 'HS256',
    typ: 'JWT'
  };

  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedPayload = base64urlEncode(JSON.stringify(payload));
  const message = `${encodedHeader}.${encodedPayload}`;

  const hmac = crypto.createHmac('sha256', customSecret);
  hmac.update(message);
  const encodedSignature = base64urlEncode(hmac.digest());

  return `${message}.${encodedSignature}`;
}

/**
 * Custom verify JWT function.
 * Returns payload if signature and validity is correct, else null.
 */
export function verifyJwt(token: string, customSecret: string = SECRET_KEY): Record<string, any> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    const message = `${encodedHeader}.${encodedPayload}`;

    // Verify HMAC-SHA256 signature
    const hmac = crypto.createHmac('sha256', customSecret);
    hmac.update(message);
    const expectedSignature = base64urlEncode(hmac.digest());

    // Use constant-time comparison to prevent timing attacks (OWASP core mitigation)
    const sigBuffer = Buffer.from(encodedSignature);
    const expectedBuffer = Buffer.from(expectedSignature);
    if (sigBuffer.length !== expectedBuffer.length || !crypto.timingSafeEqual(sigBuffer, expectedBuffer)) {
      return null;
    }

    const payload = JSON.parse(base64urlDecode(encodedPayload));

    // Verify exp (expiration) if set
    if (payload.exp && Date.now() / 1000 > payload.exp) {
      return null;
    }

    return payload;
  } catch (error) {
    return null;
  }
}

/**
 * Decode JWT token into its readable parts (for interactive UI visualization)
 */
export function decodeJwtUnverified(token: string): { header: Record<string, any>; payload: Record<string, any>; signature: string } | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    const [headerB64, payloadB64, signature] = parts;
    return {
      header: JSON.parse(base64urlDecode(headerB64)),
      payload: JSON.parse(base64urlDecode(payloadB64)),
      signature: signature
    };
  } catch (err) {
    return null;
  }
}

/**
 * Sanitizes generic user input to shield against XSS.
 * React escapes parameters implicitly, but demonstrating server-side sanitization
 * is a great secure coding demo.
 */
export function sanitizeInput(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}
