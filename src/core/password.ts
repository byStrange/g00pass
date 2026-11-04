/**
 * Random passwords from the Web Crypto CSPRNG, without modulo bias
 * (rejection sampling). Every class that is enabled appears at least once.
 */
export const PASSWORD_CLASSES = {
  lower: 'abcdefghijkmnopqrstuvwxyz',
  upper: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!#$%&*+-=?@^_~',
} as const;

export interface PasswordOptions {
  length?: number;
  symbols?: boolean;
}

function randomIndex(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0]! < limit) return buf[0]! % n;
  }
}

export function generatePassword(opts: PasswordOptions = {}): string {
  const length = Math.min(128, Math.max(8, Math.floor(opts.length ?? 20)));
  const classes: string[] = [PASSWORD_CLASSES.lower, PASSWORD_CLASSES.upper, PASSWORD_CLASSES.digits];
  if (opts.symbols ?? true) classes.push(PASSWORD_CLASSES.symbols);
  const all = classes.join('');
  const out = classes.map((c) => c[randomIndex(c.length)]!);
  while (out.length < length) out.push(all[randomIndex(all.length)]!);
  // Fisher-Yates so the guaranteed characters are not at fixed positions.
  for (let i = out.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [out[i], out[j]] = [out[j]!, out[i]!];
  }
  return out.join('');
}
