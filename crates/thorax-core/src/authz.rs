use crate::format::{
    GrantPermissionV1, KeyspaceGrantClassV1, KeyspaceSelectorV1, LabelMatcherV1,
    ManageKeyspaceGrantV1, SecretSelectorV1, TupleMatcherV1,
};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthoritySet {
    pub read: Vec<KeyspaceSelectorV1>,
    pub write: Vec<KeyspaceSelectorV1>,
    pub manage: Vec<ManageKeyspaceGrantV1>,
    pub administer: bool,
}

impl AuthoritySet {
    pub fn root() -> Self {
        Self {
            read: vec![KeyspaceSelectorV1::all()],
            write: vec![KeyspaceSelectorV1::all()],
            manage: vec![ManageKeyspaceGrantV1 {
                selector: KeyspaceSelectorV1::all(),
                grantable: vec![
                    KeyspaceGrantClassV1::Read,
                    KeyspaceGrantClassV1::Write,
                    KeyspaceGrantClassV1::Manage,
                ],
            }],
            administer: true,
        }
    }

    pub fn add_permission(&mut self, permission: &GrantPermissionV1) -> bool {
        match permission {
            GrantPermissionV1::ReadKeyspace(selector) => push_unique(&mut self.read, selector),
            GrantPermissionV1::WriteKeyspace(selector) => push_unique(&mut self.write, selector),
            GrantPermissionV1::ManageKeyspace(manage) => push_unique(&mut self.manage, manage),
            GrantPermissionV1::Administer => {
                let changed = !self.administer;
                self.administer = true;
                changed
            }
        }
    }

    // Capability hierarchy: administer ⊃ manage ⊃ write ⊃ read. Holding administer confers
    // every keyspace capability; holding manage over a keyspace confers write and read on it;
    // holding write confers read. So anyone who can administer access can always decrypt what
    // they administer — which is what lets every access-addition path auto-encrypt without a gap.
    pub fn can_read(&self, selector: &SecretSelectorV1) -> bool {
        self.administer
            || self.read.iter().any(|g| selector_matches(g, selector))
            || self.write.iter().any(|g| selector_matches(g, selector))
            || self
                .manage
                .iter()
                .any(|m| selector_matches(&m.selector, selector))
    }

    pub fn can_write(&self, selector: &SecretSelectorV1) -> bool {
        self.administer
            || self.write.iter().any(|g| selector_matches(g, selector))
            || self
                .manage
                .iter()
                .any(|m| selector_matches(&m.selector, selector))
    }

    /// Does this set hold manage authority over `selector`?
    pub fn can_manage(&self, selector: &SecretSelectorV1) -> bool {
        self.administer
            || self
                .manage
                .iter()
                .any(|m| selector_matches(&m.selector, selector))
    }

    /// Does this set confer read over the whole of `selector` (read/write/manage/administer, per hierarchy)?
    fn holds_read_over(&self, selector: &KeyspaceSelectorV1) -> bool {
        self.administer
            || self.read.iter().any(|h| selector_subsumes(h, selector))
            || self.write.iter().any(|h| selector_subsumes(h, selector))
            || self
                .manage
                .iter()
                .any(|m| selector_subsumes(&m.selector, selector))
    }

    /// Does this set confer write over the whole of `selector` (write/manage/administer, per hierarchy)?
    fn holds_write_over(&self, selector: &KeyspaceSelectorV1) -> bool {
        self.administer
            || self.write.iter().any(|h| selector_subsumes(h, selector))
            || self
                .manage
                .iter()
                .any(|m| selector_subsumes(&m.selector, selector))
    }

    pub fn can_create_permission(&self, permission: &GrantPermissionV1) -> bool {
        if self.administer {
            return true;
        }
        match permission {
            // You can only hand out a use-permission you actually hold (per the hierarchy above),
            // plus a manage grant whose `grantable` includes that class for the keyspace. So a
            // manager-with-read-grantable can both decrypt and delegate read; a pure delegator who
            // holds nothing cannot. This keeps every granter able to encrypt existing secrets to
            // the new reader (no "granted access I can't decrypt" gap), and makes deleting a read
            // grant likewise require a reader who can fully evict the removed party.
            GrantPermissionV1::ReadKeyspace(selector) => {
                self.holds_read_over(selector)
                    && self.manage.iter().any(|manage| {
                        has_grantable(&manage.grantable, KeyspaceGrantClassV1::Read)
                            && selector_subsumes(&manage.selector, selector)
                    })
            }
            GrantPermissionV1::WriteKeyspace(selector) => {
                self.holds_write_over(selector)
                    && self.manage.iter().any(|manage| {
                        has_grantable(&manage.grantable, KeyspaceGrantClassV1::Write)
                            && selector_subsumes(&manage.selector, selector)
                    })
            }
            GrantPermissionV1::ManageKeyspace(target) => self.manage.iter().any(|manage| {
                has_grantable(&manage.grantable, KeyspaceGrantClassV1::Manage)
                    && selector_subsumes(&manage.selector, &target.selector)
                    && grantable_subset(&target.grantable, &manage.grantable)
            }),
            GrantPermissionV1::Administer => self.administer,
        }
    }

    /// The permissions this authority confers, as grant permissions. Used to check that a
    /// principal adding a member to a group could have granted everything the group confers.
    pub fn as_grant_permissions(&self) -> Vec<GrantPermissionV1> {
        let mut permissions = Vec::new();
        for selector in &self.read {
            permissions.push(GrantPermissionV1::ReadKeyspace(selector.clone()));
        }
        for selector in &self.write {
            permissions.push(GrantPermissionV1::WriteKeyspace(selector.clone()));
        }
        for manage in &self.manage {
            permissions.push(GrantPermissionV1::ManageKeyspace(manage.clone()));
        }
        if self.administer {
            permissions.push(GrantPermissionV1::Administer);
        }
        permissions
    }

    pub fn merge_from(&mut self, other: &AuthoritySet) -> bool {
        let mut changed = false;
        for selector in &other.read {
            changed |= push_unique(&mut self.read, selector);
        }
        for selector in &other.write {
            changed |= push_unique(&mut self.write, selector);
        }
        for manage in &other.manage {
            changed |= push_unique(&mut self.manage, manage);
        }
        if other.administer && !self.administer {
            self.administer = true;
            changed = true;
        }
        changed
    }
}

pub fn selector_matches(grant: &KeyspaceSelectorV1, secret: &SecretSelectorV1) -> bool {
    tuple_matches(&grant.tuple, &secret.tuple)
        && grant
            .labels
            .iter()
            .all(|label| label_matches(&label.matcher, secret_label_value(secret, &label.key)))
}

pub fn selector_subsumes(parent: &KeyspaceSelectorV1, child: &KeyspaceSelectorV1) -> bool {
    tuple_subsumes(&parent.tuple, &child.tuple) && labels_subsume(parent, child)
}

pub fn grantable_subset(child: &[KeyspaceGrantClassV1], parent: &[KeyspaceGrantClassV1]) -> bool {
    child
        .iter()
        .all(|class| has_grantable(parent, class.clone()))
}

fn push_unique<T: Clone + PartialEq>(items: &mut Vec<T>, item: &T) -> bool {
    if items.contains(item) {
        false
    } else {
        items.push(item.clone());
        true
    }
}

fn has_grantable(items: &[KeyspaceGrantClassV1], class: KeyspaceGrantClassV1) -> bool {
    items.contains(&class)
}

fn tuple_matches(matcher: &TupleMatcherV1, tuple: &[String]) -> bool {
    match matcher {
        TupleMatcherV1::Any => true,
        TupleMatcherV1::Exact(exact) => exact == tuple,
        TupleMatcherV1::Prefix(prefix) => tuple.starts_with(prefix),
    }
}

fn tuple_subsumes(parent: &TupleMatcherV1, child: &TupleMatcherV1) -> bool {
    match (parent, child) {
        (TupleMatcherV1::Any, _) => true,
        (TupleMatcherV1::Prefix(parent), TupleMatcherV1::Prefix(child)) => {
            child.starts_with(parent)
        }
        (TupleMatcherV1::Prefix(parent), TupleMatcherV1::Exact(child)) => child.starts_with(parent),
        (TupleMatcherV1::Exact(parent), TupleMatcherV1::Exact(child)) => parent == child,
        _ => false,
    }
}

fn labels_subsume(parent: &KeyspaceSelectorV1, child: &KeyspaceSelectorV1) -> bool {
    for parent_label in &parent.labels {
        let child_matcher = child_label_matcher(child, &parent_label.key);
        if !label_subsumes(&parent_label.matcher, child_matcher) {
            return false;
        }
    }
    true
}

fn secret_label_value<'a>(selector: &'a SecretSelectorV1, key: &str) -> Option<&'a String> {
    selector
        .labels
        .iter()
        .find(|label| label.key == key)
        .map(|label| &label.value)
}

fn child_label_matcher<'a>(
    selector: &'a KeyspaceSelectorV1,
    key: &str,
) -> Option<&'a LabelMatcherV1> {
    selector
        .labels
        .iter()
        .find(|label| label.key == key)
        .map(|label| &label.matcher)
}

fn label_matches(matcher: &LabelMatcherV1, value: Option<&String>) -> bool {
    match matcher {
        LabelMatcherV1::Any => value.is_some(),
        LabelMatcherV1::Equals(expected) => value == Some(expected),
        LabelMatcherV1::In(values) => value.is_some_and(|actual| values.contains(actual)),
        LabelMatcherV1::Absent => value.is_none(),
    }
}

fn label_subsumes(parent: &LabelMatcherV1, child: Option<&LabelMatcherV1>) -> bool {
    match (parent, child) {
        (_, None) => false,
        (LabelMatcherV1::Any, Some(LabelMatcherV1::Any)) => true,
        (LabelMatcherV1::Any, Some(LabelMatcherV1::Equals(_))) => true,
        (LabelMatcherV1::Any, Some(LabelMatcherV1::In(_))) => true,
        (LabelMatcherV1::Any, Some(LabelMatcherV1::Absent)) => false,
        (LabelMatcherV1::Equals(parent), Some(LabelMatcherV1::Equals(child))) => parent == child,
        (LabelMatcherV1::Equals(parent), Some(LabelMatcherV1::In(child))) => {
            child.iter().all(|value| value == parent)
        }
        (LabelMatcherV1::In(parent), Some(LabelMatcherV1::Equals(child))) => parent.contains(child),
        (LabelMatcherV1::In(parent), Some(LabelMatcherV1::In(child))) => {
            let parent: BTreeSet<_> = parent.iter().collect();
            child.iter().all(|value| parent.contains(value))
        }
        (LabelMatcherV1::Absent, Some(LabelMatcherV1::Absent)) => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{KeyspaceLabelMatcherV1, LabelMatcherV1};

    #[test]
    fn prefix_subsumes_below_itself() {
        let parent = KeyspaceSelectorV1 {
            tuple: TupleMatcherV1::Prefix(vec!["app".into()]),
            labels: Vec::new(),
        };
        let child = KeyspaceSelectorV1 {
            tuple: TupleMatcherV1::Prefix(vec!["app".into(), "api".into()]),
            labels: Vec::new(),
        };
        assert!(selector_subsumes(&parent, &child));
        assert!(!selector_subsumes(&child, &parent));
    }

    #[test]
    fn label_subsumption_requires_narrower_child() {
        let parent = KeyspaceSelectorV1 {
            tuple: TupleMatcherV1::Any,
            labels: vec![KeyspaceLabelMatcherV1 {
                key: "env".to_string(),
                matcher: LabelMatcherV1::Equals("prod".into()),
            }],
        };
        let child = KeyspaceSelectorV1 {
            tuple: TupleMatcherV1::Any,
            labels: vec![KeyspaceLabelMatcherV1 {
                key: "env".to_string(),
                matcher: LabelMatcherV1::In(vec!["prod".into()]),
            }],
        };
        assert!(selector_subsumes(&parent, &child));
    }

    #[test]
    fn administer_confers_every_keyspace_capability() {
        let mut auth = AuthoritySet::default();
        auth.add_permission(&GrantPermissionV1::Administer);

        let selector = SecretSelectorV1::tuple(["app", "prod", "db"]);
        assert!(auth.can_read(&selector));
        assert!(auth.can_write(&selector));
        assert!(auth.can_manage(&selector));

        assert!(
            auth.can_create_permission(&GrantPermissionV1::ReadKeyspace(KeyspaceSelectorV1::all()))
        );
        assert!(auth
            .can_create_permission(&GrantPermissionV1::WriteKeyspace(KeyspaceSelectorV1::all())));
        assert!(
            auth.can_create_permission(&GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
                selector: KeyspaceSelectorV1::all(),
                grantable: vec![
                    KeyspaceGrantClassV1::Read,
                    KeyspaceGrantClassV1::Write,
                    KeyspaceGrantClassV1::Manage,
                ],
            }))
        );
        assert!(auth.can_create_permission(&GrantPermissionV1::Administer));
    }

    #[test]
    fn manage_and_write_confer_lower_capabilities() {
        let selector = SecretSelectorV1::tuple(["app", "prod", "db"]);

        let mut manager = AuthoritySet::default();
        manager.add_permission(&GrantPermissionV1::ManageKeyspace(ManageKeyspaceGrantV1 {
            selector: KeyspaceSelectorV1::prefix(["app"]),
            grantable: vec![KeyspaceGrantClassV1::Read],
        }));
        assert!(manager.can_manage(&selector));
        assert!(manager.can_write(&selector));
        assert!(manager.can_read(&selector));

        let mut writer = AuthoritySet::default();
        writer.add_permission(&GrantPermissionV1::WriteKeyspace(
            KeyspaceSelectorV1::prefix(["app"]),
        ));
        assert!(!writer.can_manage(&selector));
        assert!(writer.can_write(&selector));
        assert!(writer.can_read(&selector));
    }
}
