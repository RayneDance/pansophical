//! Permission bit flags (`r/w/x`) and TOML parsing for both
//! short form (`"rw"`) and verb list (`["read", "write"]`).

use bitflags::bitflags;
use serde::de::{self, Deserializer, Visitor};
use std::fmt;

bitflags! {
    /// Unix-style permission bits. Stored as a `u8` internally.
    ///
    /// | Bit | Short | Verb aliases |
    /// |-----|-------|--------------|
    /// | 4   | `r`   | `read`       |
    /// | 2   | `w`   | `write`      |
    /// | 1   | `x`   | `execute`, `connect`, `traverse`, `inject`, `signal` |
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Perm: u8 {
        const READ    = 0b100;
        const WRITE   = 0b010;
        const EXECUTE = 0b001;
    }
}

impl Perm {
    /// Parse a single verb string to a `Perm` bit.
    pub fn from_verb(verb: &str) -> Option<Perm> {
        match verb {
            "r" | "read" => Some(Perm::READ),
            "w" | "write" => Some(Perm::WRITE),
            "x" | "execute" | "connect" | "traverse" | "inject" | "signal" => {
                Some(Perm::EXECUTE)
            }
            _ => None,
        }
    }

    /// Parse the short form: `"rw"`, `"rwx"`, `"r"`, etc.
    pub fn from_short(s: &str) -> Result<Perm, String> {
        let mut perm = Perm::empty();
        for ch in s.chars() {
            match ch {
                'r' => perm |= Perm::READ,
                'w' => perm |= Perm::WRITE,
                'x' => perm |= Perm::EXECUTE,
                other => return Err(format!("unknown permission character: '{other}'")),
            }
        }
        if perm.is_empty() {
            return Err("permission string is empty".into());
        }
        Ok(perm)
    }

    /// Parse a verb list: `["read", "write"]`.
    pub fn from_verb_list(verbs: &[String]) -> Result<Perm, String> {
        let mut perm = Perm::empty();
        for verb in verbs {
            match Perm::from_verb(verb) {
                Some(p) => perm |= p,
                None => return Err(format!("unknown permission verb: \"{verb}\"")),
            }
        }
        if perm.is_empty() {
            return Err("permission verb list is empty".into());
        }
        Ok(perm)
    }
}

impl fmt::Display for Perm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.contains(Perm::READ) {
            write!(f, "r")?;
        }
        if self.contains(Perm::WRITE) {
            write!(f, "w")?;
        }
        if self.contains(Perm::EXECUTE) {
            write!(f, "x")?;
        }
        Ok(())
    }
}

impl serde::Serialize for Perm {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

/// Custom deserializer: accepts either a short string `"rw"` or a verb list `["read", "write"]`.
impl<'de> serde::Deserialize<'de> for Perm {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PermVisitor;

        impl<'de> Visitor<'de> for PermVisitor {
            type Value = Perm;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(r#"a permission string like "rw" or a list like ["read", "write"]"#)
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Perm, E> {
                Perm::from_short(value).map_err(de::Error::custom)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Perm, A::Error> {
                let mut verbs = Vec::new();
                while let Some(v) = seq.next_element::<String>()? {
                    verbs.push(v);
                }
                Perm::from_verb_list(&verbs).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_any(PermVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_rw() {
        assert_eq!(Perm::from_short("rw").unwrap(), Perm::READ | Perm::WRITE);
    }

    #[test]
    fn short_form_rwx() {
        assert_eq!(
            Perm::from_short("rwx").unwrap(),
            Perm::READ | Perm::WRITE | Perm::EXECUTE
        );
    }

    #[test]
    fn short_form_r() {
        assert_eq!(Perm::from_short("r").unwrap(), Perm::READ);
    }

    #[test]
    fn short_form_invalid() {
        assert!(Perm::from_short("z").is_err());
    }

    #[test]
    fn short_form_empty() {
        assert!(Perm::from_short("").is_err());
    }

    #[test]
    fn verb_list() {
        let verbs = vec!["read".into(), "write".into()];
        assert_eq!(Perm::from_verb_list(&verbs).unwrap(), Perm::READ | Perm::WRITE);
    }

    #[test]
    fn verb_aliases_all_map_to_execute() {
        for alias in &["execute", "connect", "traverse", "inject", "signal"] {
            assert_eq!(Perm::from_verb(alias), Some(Perm::EXECUTE));
        }
    }

    #[test]
    fn display_round_trip() {
        let perm = Perm::READ | Perm::WRITE;
        assert_eq!(perm.to_string(), "rw");
        assert_eq!(Perm::from_short(&perm.to_string()).unwrap(), perm);
    }

    #[test]
    fn intersection() {
        let key_grants = Perm::READ | Perm::WRITE;
        let tool_needs = Perm::READ;
        let actual = key_grants & tool_needs;
        assert_eq!(actual, Perm::READ);
    }

    #[test]
    fn superset_check() {
        let grant = Perm::READ | Perm::WRITE;
        let request = Perm::READ;
        assert!(grant.contains(request));
    }

    #[test]
    fn deserialize_short() {
        let perm: Perm = serde_json::from_str(r#""rw""#).unwrap();
        assert_eq!(perm, Perm::READ | Perm::WRITE);
    }

    #[test]
    fn deserialize_verb_list() {
        let perm: Perm = serde_json::from_str(r#"["read", "execute"]"#).unwrap();
        assert_eq!(perm, Perm::READ | Perm::EXECUTE);
    }
}
