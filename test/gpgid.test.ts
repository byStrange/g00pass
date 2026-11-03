import { describe, expect, it } from 'vitest';
import {
  MemoryStore,
  NoRecipientsError,
  StorePathError,
  findGpgIdForEntry,
  findGpgIdForFolder,
  isHiddenEntry,
  keyIdKind,
  listGovernedEntries,
  nestedGpgIdFolders,
  normalizeKeyId,
  normalizePath,
  parseGpgId,
  recipientIds,
  serializeGpgId,
} from '../src/core';

const has = (files: string[]) => {
  const s = new Set(files);
  return (p: string) => s.has(p);
};

describe('parseGpgId (pass/gopass compatible)', () => {
  it('ignores blanks, whole-line and trailing comments, trims, handles CRLF', () => {
    const text = [
      '# global admins',
      '',
      '   ABCDEF0123456789ABCDEF0123456789ABCDEF01   ',
      'alice@example.com # Alice',
      '\t0xDEADBEEFDEADBEEF\t',
      '   # indented comment',
      'bob@example.com#no-space-comment',
      '',
    ].join('\r\n');
    expect(parseGpgId(text).map((r) => r.id)).toEqual([
      'ABCDEF0123456789ABCDEF0123456789ABCDEF01',
      'alice@example.com',
      '0xDEADBEEFDEADBEEF',
      'bob@example.com',
    ]);
  });

  it('records line numbers and g00pass flags from trailing comments only', () => {
    const r = parseGpgId('A1B2C3D4\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF # recovery g00pass:escrow g00pass:other\n# g00pass:escrow\n');
    expect(r).toEqual([
      { id: 'A1B2C3D4', flags: [], line: 1 },
      { id: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', flags: ['escrow', 'other'], line: 2 },
    ]);
  });

  it('empty or comment-only file has no recipients', () => {
    expect(parseGpgId('')).toEqual([]);
    expect(parseGpgId('# nothing\n\n   \n')).toEqual([]);
  });

  it('recipientIds dedupes by normalized id, keeping first spelling', () => {
    const r = parseGpgId('0xabcdef0123456789\nABCDEF0123456789\nAlice@Example.com\nalice@example.com\n');
    expect(recipientIds(r)).toEqual(['0xabcdef0123456789', 'Alice@Example.com']);
  });
});

describe('normalizeKeyId / keyIdKind', () => {
  it('normalizes hex ids', () => {
    expect(normalizeKeyId('0xabcd1234')).toBe('ABCD1234');
    expect(normalizeKeyId('ABCD EF01 2345 6789 ABCD  EF01 2345 6789 ABCD EF01')).toBe('ABCDEF0123456789ABCDEF0123456789ABCDEF01');
    expect(normalizeKeyId(' Bob@X.org ')).toBe('bob@x.org');
  });
  it('classifies ids', () => {
    expect(keyIdKind('A'.repeat(40))).toBe('fingerprint');
    expect(keyIdKind('a'.repeat(64))).toBe('fingerprint');
    expect(keyIdKind('0x' + 'b'.repeat(16))).toBe('long-id');
    expect(keyIdKind('DEADBEEF')).toBe('short-id');
    expect(keyIdKind('deadbeefcafe')).toBe('user-id');
    expect(keyIdKind('x@y.z')).toBe('user-id');
  });
});

describe('serializeGpgId', () => {
  it('is deterministic, dedupes, merges flags, ends with newline', () => {
    const out = serializeGpgId(['AAAA1111', { id: 'bbbb2222bbbb2222' }, { id: '0xaaaa1111', flags: ['escrow'] }]);
    expect(out).toBe('AAAA1111 # g00pass:escrow\nbbbb2222bbbb2222\n');
    expect(parseGpgId(out)).toEqual([
      { id: 'AAAA1111', flags: ['escrow'], line: 1 },
      { id: 'bbbb2222bbbb2222', flags: [], line: 2 },
    ]);
  });
  it('rejects empty sets and ids containing # or newlines', () => {
    expect(() => serializeGpgId([])).toThrow();
    expect(() => serializeGpgId(['a#b'])).toThrow();
    expect(() => serializeGpgId(['a\nb'])).toThrow();
    expect(() => serializeGpgId([{ id: 'A', flags: ['Bad Flag'] }])).toThrow();
  });
});

describe('nearest .gpg-id resolution', () => {
  const files = [
    '.gpg-id',
    'top.gpg',
    'infra/.gpg-id',
    'infra/db.gpg',
    'infra/deep/er/x.gpg',
    'infra/prod/.gpg-id',
    'infra/prod/key.gpg',
    'infra2/y.gpg',
    'clients/x/.gpg-id',
    'clients/x/a.gpg',
    'clients/y/b.gpg',
    'a/.gpg-id',
    'a/b.gpg',
    'a/b/.gpg-id',
    'a/b/c.gpg',
  ];
  const h = has(files);

  it.each([
    ['top', '.gpg-id'],
    ['top.gpg', '.gpg-id'],
    ['infra/db', 'infra/.gpg-id'],
    ['infra/deep/er/x', 'infra/.gpg-id'],
    ['infra/prod/key', 'infra/prod/.gpg-id'],
    ['infra2/y', '.gpg-id'], // prefix-similar folder must not match infra/
    ['clients/x/a', 'clients/x/.gpg-id'],
    ['clients/y/b', '.gpg-id'], // sibling does not leak
    ['/infra//prod/./key.gpg', 'infra/prod/.gpg-id'], // normalization
    ['a/b', 'a/.gpg-id'], // pass semantics: entry a/b.gpg lives in a/, not a/b/
    ['a/b/c', 'a/b/.gpg-id'],
    ['new/folder/entry', '.gpg-id'], // write path for not-yet-existing folders
  ])('%s -> %s', (entry, want) => {
    expect(findGpgIdForEntry(h, entry)).toBe(want);
  });

  it('folder lookup starts at the folder itself', () => {
    expect(findGpgIdForFolder(h, 'infra/prod')).toBe('infra/prod/.gpg-id');
    expect(findGpgIdForFolder(h, 'infra/prod/sub')).toBe('infra/prod/.gpg-id');
    expect(findGpgIdForFolder(h, '')).toBe('.gpg-id');
    expect(findGpgIdForFolder(h, 'clients/y')).toBe('.gpg-id');
  });

  it('throws NoRecipientsError when no .gpg-id up to root', () => {
    const h2 = has(['sub/.gpg-id', 'sub/a.gpg', 'b.gpg']);
    expect(findGpgIdForEntry(h2, 'sub/a')).toBe('sub/.gpg-id');
    expect(() => findGpgIdForEntry(h2, 'b')).toThrow(NoRecipientsError);
    expect(() => findGpgIdForEntry(h2, 'other/c')).toThrow(NoRecipientsError);
    expect(() => findGpgIdForFolder(h2, '')).toThrow(NoRecipientsError);
  });

  it('rejects path traversal and empty entries', () => {
    expect(() => findGpgIdForEntry(h, '../etc/passwd')).toThrow(StorePathError);
    expect(() => findGpgIdForEntry(h, 'infra/../../x')).toThrow(StorePathError);
    expect(() => findGpgIdForEntry(h, '')).toThrow(StorePathError);
    expect(() => normalizePath('a\\b')).toThrow(StorePathError);
    expect(() => normalizePath('a\0b')).toThrow(StorePathError);
  });

  it('isHiddenEntry flags dot-files and dot-folders', () => {
    expect(isHiddenEntry('team/.g00pass-rotation.gpg')).toBe(true);
    expect(isHiddenEntry('.hidden/x.gpg')).toBe(true);
    expect(isHiddenEntry('team/db.gpg')).toBe(false);
  });

  it('a folder named ".gpg-id.gpg" style entry is still an entry', () => {
    expect(findGpgIdForEntry(has(['.gpg-id', 'x/.gpg-id.gpg']), 'x/.gpg-id')).toBe('.gpg-id');
  });
});

describe('governed entries (re-encrypt scope)', () => {
  const store = new MemoryStore({
    '.gpg-id': 'X',
    'root.gpg': 'c',
    'infra/.gpg-id': 'A',
    'infra/a.gpg': 'c',
    'infra/sub/b.gpg': 'c', // no own .gpg-id: governed by infra
    'infra/prod/.gpg-id': 'B',
    'infra/prod/c.gpg': 'c',
    'infra/prod/deeper/d.gpg': 'c',
    'infra/notes.txt': 'not an entry',
    'infra/.gpg': 'not an entry (no name)',
    'infrastructure/e.gpg': 'c',
    '.public-keys/odd.gpg': 'key file, not an entry',
    '.g00pass/x.gpg': 'metadata dir, not an entry',
  });
  it('stops at nested .gpg-id boundaries', () => {
    expect(listGovernedEntries(store, 'infra')).toEqual(['infra/a.gpg', 'infra/sub/b.gpg']);
    expect(listGovernedEntries(store, 'infra/prod')).toEqual(['infra/prod/c.gpg', 'infra/prod/deeper/d.gpg']);
    expect(listGovernedEntries(store, '')).toEqual(['infrastructure/e.gpg', 'root.gpg']);
    expect(nestedGpgIdFolders(store, '')).toEqual(['infra', 'infra/prod']);
    expect(nestedGpgIdFolders(store, 'infra')).toEqual(['infra/prod']);
  });
});
