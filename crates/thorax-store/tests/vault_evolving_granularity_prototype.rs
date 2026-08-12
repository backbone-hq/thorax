//! Prototype tests for cord `Evolving` granularity on nested extension-point enums.

use cord::{Cord, Evolving};

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
struct PrincipalId(u32);

// Variant A: permission is a bare, non-evolving enum.
mod bare {
    use super::*;

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum Body {
        #[cord(index = 0)]
        Grant(Grant),
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub struct Grant {
        pub issuer: PrincipalId,
        pub subject: PrincipalId,
        pub permission: Permission,
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum Permission {
        #[cord(index = 0)]
        Read,
        #[cord(index = 1)]
        Write,
    }

    // Future binary adds a permission kind. Same body/grant layout otherwise.
    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub struct GrantFuture {
        pub issuer: PrincipalId,
        pub subject: PrincipalId,
        pub permission: PermissionFuture,
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum PermissionFuture {
        #[cord(index = 0)]
        Read,
        #[cord(index = 1)]
        Write,
        #[cord(index = 2)]
        Administer,
    }
}

// The body wrapper as the vault has it: `Evolving<Body>` at the record level.
#[derive(Cord, Clone, Debug, PartialEq, Eq)]
struct RecordBare {
    body: Evolving<bare::Body>,
}

#[test]
fn bare_inner_enum_degrades_the_whole_body() {
    // Newer binary emits a grant whose permission is the new Administer kind.
    // We hand-build the equivalent record by serializing a future-shaped body.
    #[derive(Cord)]
    struct RecordFuture {
        body: Evolving<BodyFuture>,
    }
    #[derive(Cord)]
    enum BodyFuture {
        #[cord(index = 0)]
        Grant(bare::GrantFuture),
    }

    let future = RecordFuture {
        body: Evolving::new(BodyFuture::Grant(bare::GrantFuture {
            issuer: PrincipalId(1),
            subject: PrincipalId(2),
            permission: bare::PermissionFuture::Administer,
        })),
    };
    let bytes = cord::serialize(&future).expect("serialize future");

    // Old binary reads it. Because Permission isn't evolving, decoding the Grant
    // fails on the unknown permission index, so the ENTIRE body is Unknown.
    let old: RecordBare = cord::deserialize(&bytes).expect("old deserialize");
    assert!(
        old.body.is_unknown(),
        "unknown inner permission collapses the whole body to Unknown — \
         old binary can't even see this is a grant"
    );

    // Still round-trips byte-identically (so signatures still verify)…
    assert_eq!(bytes, cord::serialize(&old).unwrap());
    // …but all structured visibility into the record is lost. That's the cost.
}

// Variant B: permission is `Evolving`, so it degrades in isolation.
mod wrapped {
    use super::*;

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum Body {
        #[cord(index = 0)]
        Grant(Grant),
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub struct Grant {
        pub issuer: PrincipalId,
        pub subject: PrincipalId,
        pub permission: Evolving<Permission>,
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum Permission {
        #[cord(index = 0)]
        Read,
        #[cord(index = 1)]
        Write,
    }

    impl Permission {
        /// Fail-closed authz: an unknown permission grants NOTHING.
        pub fn grants_admin(perm: &Evolving<Permission>) -> bool {
            matches!(perm.known(), Some(Permission::Write)) // (toy rule)
        }
    }

    #[derive(Cord, Clone, Debug, PartialEq, Eq)]
    pub enum PermissionFuture {
        #[cord(index = 0)]
        Read,
        #[cord(index = 1)]
        Write,
        #[cord(index = 2)]
        Administer,
    }
}

#[derive(Cord, Clone, Debug, PartialEq, Eq)]
struct RecordWrapped {
    body: Evolving<wrapped::Body>,
}

#[test]
fn wrapped_inner_enum_degrades_in_isolation_and_fails_closed() {
    #[derive(Cord)]
    struct GrantFuture {
        issuer: PrincipalId,
        subject: PrincipalId,
        permission: Evolving<wrapped::PermissionFuture>,
    }
    #[derive(Cord)]
    enum BodyFuture {
        #[cord(index = 0)]
        Grant(GrantFuture),
    }
    #[derive(Cord)]
    struct RecordFuture {
        body: Evolving<BodyFuture>,
    }

    let future = RecordFuture {
        body: Evolving::new(BodyFuture::Grant(GrantFuture {
            issuer: PrincipalId(1),
            subject: PrincipalId(2),
            permission: Evolving::new(wrapped::PermissionFuture::Administer),
        })),
    };
    let bytes = cord::serialize(&future).expect("serialize future");

    // Old binary reads it. Now the Grant decodes: only the permission is opaque.
    let old: RecordWrapped = cord::deserialize(&bytes).expect("old deserialize");
    let body = old.body.known().expect("body is still readable as a Grant");
    let wrapped::Body::Grant(grant) = body;
    assert_eq!(grant.issuer, PrincipalId(1), "issuer still visible");
    assert_eq!(grant.subject, PrincipalId(2), "subject still visible");
    assert!(
        grant.permission.is_unknown(),
        "only the unknown permission is opaque"
    );

    // Fail closed: the unknown permission must grant nothing.
    assert!(
        !wrapped::Permission::grants_admin(&grant.permission),
        "unknown permission must deny (fail closed), never grant"
    );

    // And still byte-identical on rewrite.
    assert_eq!(bytes, cord::serialize(&old).unwrap());
}
