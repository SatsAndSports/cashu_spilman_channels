import { afterEach, describe, expect, it, vi } from 'vitest';

import { createInMemoryStores, createSpilmanHost } from 'cdk-spilman-kit';

describe('mint error handling', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it('preserves status and raw NUT-00 JSON as response evidence', async () => {
    const nut00Error = '{"code":12001,"detail":"Unknown Keyset"}';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(nut00Error, { status: 400 })));

    const host = createSpilmanHost({
      secretKeyHex: '0000000000000000000000000000000000000000000000000000000000000001',
      mints: { 'http://localhost:3338': ['sat'] },
      pricing: { sat: { min_capacity: 1, variables: {} } },
      stores: createInMemoryStores(),
    });

    expect(JSON.parse(await host.callMintSwap('http://localhost:3338', '{}'))).toEqual({status: 400, body: nut00Error});
  });
});
