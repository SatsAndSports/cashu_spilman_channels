import { afterEach, describe, expect, it, vi } from 'vitest';

import { createInMemoryStores, createSpilmanHost } from 'cdk-spilman-kit';

describe('mint error handling', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('preserves raw NUT-00 mint JSON in callMintSwap rejections', async () => {
    const nut00Error = '{"code":12001,"detail":"Unknown Keyset"}';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      status: 400,
      text: async () => nut00Error,
    }));

    const host = createSpilmanHost({
      secretKeyHex: '0000000000000000000000000000000000000000000000000000000000000001',
      mints: { 'http://localhost:3338': ['sat'] },
      pricing: { sat: { min_capacity: 1, variables: {} } },
      stores: createInMemoryStores(),
    });

    await expect(host.callMintSwap('http://localhost:3338', '{}')).rejects.toBe(nut00Error);
  });
});
