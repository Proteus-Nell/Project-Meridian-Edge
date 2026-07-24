// Comparison helpers for secret material. Both inputs here are values the
// local user just typed, so no remote attacker can time this call - the
// constant-time discipline is defense-in-depth hygiene (and keeps the CI
// habit of never comparing secrets with early-exit equality). JS strings are
// immutable and cannot be zeroized; the transient byte copies made for the
// comparison are wiped, which is the best the platform allows (documented
// limitation).

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  }
  return diff === 0;
}

export function secretStringsEqual(a: string, b: string): boolean {
  const bytesA = new TextEncoder().encode(a);
  const bytesB = new TextEncoder().encode(b);
  try {
    return constantTimeEqual(bytesA, bytesB);
  } finally {
    bytesA.fill(0);
    bytesB.fill(0);
  }
}
