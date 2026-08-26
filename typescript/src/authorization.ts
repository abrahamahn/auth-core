export interface RoleDefinition<Role extends string, Permission extends string> {
  readonly role: Role;
  readonly grants?: readonly Permission[];
  readonly inherits?: readonly Role[];
}

export type AuthorizationDecision<Role extends string, Permission extends string> =
  | {
      readonly authorized: true;
      readonly role: Role;
      readonly permission: Permission;
    }
  | {
      readonly authorized: false;
      readonly role: Role;
      readonly permission: Permission;
      readonly reason: 'unknown-role' | 'missing-permission';
    };

/**
 * Immutable role/permission policy with validated transitive role inheritance.
 *
 * Applications own their role and permission names. This class owns only the
 * reusable RBAC mechanics: validation, inheritance, and all/any decisions.
 */
export class RbacPolicy<Role extends string, Permission extends string> {
  readonly #permissionsByRole = new Map<Role, ReadonlySet<Permission>>();
  readonly #rolesByRole = new Map<Role, ReadonlySet<Role>>();

  public constructor(definitions: readonly RoleDefinition<Role, Permission>[]) {
    const definitionsByRole = new Map<Role, RoleDefinition<Role, Permission>>();
    for (const definition of definitions) {
      if (definition.role.trim() === '') throw new Error('role must not be empty');
      if (definitionsByRole.has(definition.role)) {
        throw new Error(`duplicate role definition: ${definition.role}`);
      }
      definitionsByRole.set(definition.role, definition);
    }

    const visiting = new Set<Role>();
    const resolve = (
      role: Role,
    ): { readonly permissions: ReadonlySet<Permission>; readonly roles: ReadonlySet<Role> } => {
      const cachedPermissions = this.#permissionsByRole.get(role);
      const cachedRoles = this.#rolesByRole.get(role);
      if (cachedPermissions !== undefined && cachedRoles !== undefined) {
        return { permissions: cachedPermissions, roles: cachedRoles };
      }
      const definition = definitionsByRole.get(role);
      if (definition === undefined) throw new Error(`unknown inherited role: ${role}`);
      if (visiting.has(role)) throw new Error(`role inheritance cycle includes: ${role}`);

      visiting.add(role);
      const permissions = new Set<Permission>(definition.grants ?? []);
      const roles = new Set<Role>([role]);
      for (const parent of definition.inherits ?? []) {
        const inherited = resolve(parent);
        for (const permission of inherited.permissions) permissions.add(permission);
        for (const inheritedRole of inherited.roles) roles.add(inheritedRole);
      }
      visiting.delete(role);

      this.#permissionsByRole.set(role, permissions);
      this.#rolesByRole.set(role, roles);
      return { permissions, roles };
    };

    for (const role of definitionsByRole.keys()) resolve(role);
  }

  public hasRole(role: Role, requiredRole: Role): boolean {
    return this.#rolesByRole.get(role)?.has(requiredRole) ?? false;
  }

  public hasPermission(role: Role, permission: Permission): boolean {
    return this.#permissionsByRole.get(role)?.has(permission) ?? false;
  }

  public hasEveryPermission(role: Role, permissions: readonly Permission[]): boolean {
    return permissions.every((permission) => this.hasPermission(role, permission));
  }

  public hasAnyPermission(role: Role, permissions: readonly Permission[]): boolean {
    return permissions.some((permission) => this.hasPermission(role, permission));
  }

  public evaluate(role: Role, permission: Permission): AuthorizationDecision<Role, Permission> {
    if (!this.#permissionsByRole.has(role)) {
      return { authorized: false, role, permission, reason: 'unknown-role' };
    }
    if (!this.hasPermission(role, permission)) {
      return { authorized: false, role, permission, reason: 'missing-permission' };
    }
    return { authorized: true, role, permission };
  }
}
