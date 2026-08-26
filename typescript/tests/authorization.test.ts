import { describe, expect, it } from 'vitest';

import { RbacPolicy } from '../src/authorization.js';

type Role = 'viewer' | 'editor' | 'admin';
type Permission = 'document:read' | 'document:write' | 'users:manage';

const policy = new RbacPolicy<Role, Permission>([
  { role: 'viewer', grants: ['document:read'] },
  { role: 'editor', grants: ['document:write'], inherits: ['viewer'] },
  { role: 'admin', grants: ['users:manage'], inherits: ['editor'] },
]);

describe('RbacPolicy', () => {
  it('resolves transitive role and permission inheritance', () => {
    expect(policy.hasRole('admin', 'viewer')).toBe(true);
    expect(policy.hasPermission('admin', 'document:read')).toBe(true);
    expect(policy.hasEveryPermission('editor', ['document:read', 'document:write'])).toBe(true);
    expect(policy.hasAnyPermission('viewer', ['document:write', 'document:read'])).toBe(true);
  });

  it('returns explicit denial reasons', () => {
    expect(policy.evaluate('viewer', 'document:write')).toEqual({
      authorized: false,
      role: 'viewer',
      permission: 'document:write',
      reason: 'missing-permission',
    });
    expect(policy.evaluate('missing' as Role, 'document:read')).toMatchObject({
      authorized: false,
      reason: 'unknown-role',
    });
  });

  it('rejects duplicate, unknown, and cyclic role definitions', () => {
    expect(
      () =>
        new RbacPolicy([
          { role: 'member' },
          { role: 'member' },
        ]),
    ).toThrow('duplicate role');
    expect(() => new RbacPolicy([{ role: 'member', inherits: ['missing'] }])).toThrow(
      'unknown inherited role',
    );
    expect(
      () =>
        new RbacPolicy([
          { role: 'left', inherits: ['right'] },
          { role: 'right', inherits: ['left'] },
        ]),
    ).toThrow('inheritance cycle');
  });
});
