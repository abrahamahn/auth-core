use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleDefinition {
    pub role: String,
    pub grants: Vec<String>,
    pub inherits: Vec<String>,
}

impl RoleDefinition {
    #[must_use]
    pub fn new(role: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            grants: Vec::new(),
            inherits: Vec::new(),
        }
    }

    #[must_use]
    pub fn grants(mut self, grants: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.grants = grants.into_iter().map(Into::into).collect();
        self
    }

    #[must_use]
    pub fn inherits(mut self, roles: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.inherits = roles.into_iter().map(Into::into).collect();
        self
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RbacError {
    EmptyRole,
    DuplicateRole(String),
    UnknownInheritedRole(String),
    InheritanceCycle(String),
}

impl Display for RbacError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRole => formatter.write_str("role must not be empty"),
            Self::DuplicateRole(role) => write!(formatter, "duplicate role definition: {role}"),
            Self::UnknownInheritedRole(role) => write!(formatter, "unknown inherited role: {role}"),
            Self::InheritanceCycle(role) => {
                write!(formatter, "role inheritance cycle includes: {role}")
            }
        }
    }
}

impl Error for RbacError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizationDecision {
    Authorized,
    UnknownRole,
    MissingPermission,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RbacPolicy {
    permissions_by_role: HashMap<String, HashSet<String>>,
    roles_by_role: HashMap<String, HashSet<String>>,
}

impl RbacPolicy {
    /// Builds and validates an immutable role hierarchy.
    ///
    /// # Errors
    ///
    /// Returns [`RbacError`] when a role is empty or duplicated, an inherited role is unknown,
    /// or the inheritance graph contains a cycle.
    pub fn new(definitions: impl IntoIterator<Item = RoleDefinition>) -> Result<Self, RbacError> {
        let mut definitions_by_role = HashMap::new();
        let mut definition_order = Vec::new();
        for definition in definitions {
            if definition.role.trim().is_empty() {
                return Err(RbacError::EmptyRole);
            }
            if definitions_by_role.contains_key(&definition.role) {
                return Err(RbacError::DuplicateRole(definition.role));
            }
            definition_order.push(definition.role.clone());
            definitions_by_role.insert(definition.role.clone(), definition);
        }

        let mut permissions_by_role = HashMap::new();
        let mut roles_by_role = HashMap::new();
        let mut visiting = HashSet::new();
        for role in &definition_order {
            resolve_role(
                role,
                &definitions_by_role,
                &mut permissions_by_role,
                &mut roles_by_role,
                &mut visiting,
            )?;
        }
        Ok(Self {
            permissions_by_role,
            roles_by_role,
        })
    }

    #[must_use]
    pub fn has_role(&self, role: &str, required_role: &str) -> bool {
        self.roles_by_role
            .get(role)
            .is_some_and(|roles| roles.contains(required_role))
    }

    #[must_use]
    pub fn has_permission(&self, role: &str, permission: &str) -> bool {
        self.permissions_by_role
            .get(role)
            .is_some_and(|permissions| permissions.contains(permission))
    }

    #[must_use]
    pub fn has_every_permission<'a>(
        &self,
        role: &str,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        permissions
            .into_iter()
            .all(|permission| self.has_permission(role, permission))
    }

    #[must_use]
    pub fn has_any_permission<'a>(
        &self,
        role: &str,
        permissions: impl IntoIterator<Item = &'a str>,
    ) -> bool {
        permissions
            .into_iter()
            .any(|permission| self.has_permission(role, permission))
    }

    #[must_use]
    pub fn evaluate(&self, role: &str, permission: &str) -> AuthorizationDecision {
        if !self.permissions_by_role.contains_key(role) {
            return AuthorizationDecision::UnknownRole;
        }
        if self.has_permission(role, permission) {
            AuthorizationDecision::Authorized
        } else {
            AuthorizationDecision::MissingPermission
        }
    }
}

fn resolve_role(
    role: &str,
    definitions: &HashMap<String, RoleDefinition>,
    permissions_by_role: &mut HashMap<String, HashSet<String>>,
    roles_by_role: &mut HashMap<String, HashSet<String>>,
    visiting: &mut HashSet<String>,
) -> Result<(), RbacError> {
    if permissions_by_role.contains_key(role) {
        return Ok(());
    }
    let definition = definitions
        .get(role)
        .ok_or_else(|| RbacError::UnknownInheritedRole(role.to_owned()))?;
    if !visiting.insert(role.to_owned()) {
        return Err(RbacError::InheritanceCycle(role.to_owned()));
    }

    let mut permissions = definition.grants.iter().cloned().collect::<HashSet<_>>();
    let mut roles = HashSet::from([role.to_owned()]);
    for parent in &definition.inherits {
        resolve_role(
            parent,
            definitions,
            permissions_by_role,
            roles_by_role,
            visiting,
        )?;
        permissions.extend(
            permissions_by_role
                .get(parent)
                .expect("resolved parent permissions")
                .iter()
                .cloned(),
        );
        roles.extend(
            roles_by_role
                .get(parent)
                .expect("resolved parent roles")
                .iter()
                .cloned(),
        );
    }
    visiting.remove(role);
    permissions_by_role.insert(role.to_owned(), permissions);
    roles_by_role.insert(role.to_owned(), roles);
    Ok(())
}
