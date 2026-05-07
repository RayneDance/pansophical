//! Intersection computation: actual_grant = tool_needs ∩ key_grants.
//!
//! The core intersection logic is embedded in `evaluate_single` in the
//! parent module. This module re-exports and documents the principle.
//!
//! ## The Intersection Principle
//!
//! An `AccessRequest` is satisfied when there exists a matching grant rule
//! whose path glob contains the requested path AND whose `Perm` bits are
//! a **superset** of the requested bits.
//!
//! The actual grant for that request is the *requested* bits (not the
//! grant's broader bits).
//!
//! Example:
//! - Tool asks `r` on `/workspace/src/main.rs`
//! - Key grants `rw` on `/workspace/**`
//! - Actual grant = `r` on `/workspace/src/main.rs` (not `rw`)
//!
//! This enforces Principle of Least Privilege automatically.

use crate::config::perm::Perm;

/// Compute the intersection of requested permissions and granted permissions.
///
/// Returns `Some(actual)` if the grant covers the request, `None` otherwise.
/// The actual grant is always the *requested* bits, capped by the grant.
pub fn intersect(requested: Perm, granted: Perm) -> Option<Perm> {
    if granted.contains(requested) {
        Some(requested)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        assert_eq!(intersect(Perm::READ, Perm::READ), Some(Perm::READ));
    }

    #[test]
    fn subset_grant() {
        // Request r, grant rw → actual r.
        assert_eq!(
            intersect(Perm::READ, Perm::READ | Perm::WRITE),
            Some(Perm::READ)
        );
    }

    #[test]
    fn insufficient_grant() {
        // Request rw, grant r → denied.
        assert_eq!(intersect(Perm::READ | Perm::WRITE, Perm::READ), None);
    }

    #[test]
    fn full_grant() {
        let all = Perm::READ | Perm::WRITE | Perm::EXECUTE;
        assert_eq!(intersect(Perm::READ, all), Some(Perm::READ));
        assert_eq!(intersect(Perm::READ | Perm::WRITE, all), Some(Perm::READ | Perm::WRITE));
    }

    #[test]
    fn empty_request() {
        assert_eq!(intersect(Perm::empty(), Perm::READ), Some(Perm::empty()));
    }
}
