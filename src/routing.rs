//! Ordered process rules choose explicit egress without falling back around a failed tunnel.

use serde::{Deserialize, Serialize};

/// An egress policy chooses the configured server, local network, or rejection.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Policy {
    #[default]
    Proxy,
    Direct,
    Reject,
}

/// A matcher compares an exact executable path or process name.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Matcher {
    ProcessName,
    ProcessPath,
}

/// A process identity records only locally observed ownership of the SOCKS control socket.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: Option<u32>,
    pub name: Option<String>,
    pub path: Option<String>,
}

/// One enabled rule assigns an egress policy to an exact process identity.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub matcher: Matcher,
    pub value: String,
    pub policy: Policy,
    pub enabled: bool,
}

/// Routing applies the first enabled match and otherwise uses its explicit default policy.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    #[serde(default)]
    pub default_policy: Policy,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Routing validation bounds configuration size and forbids ambiguous empty matchers.
impl Routing {
    /// Reject excessive or malformed rules before opening a listener.
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.rules.len() <= 256,
            "at most 256 process rules are allowed"
        );
        for rule in &self.rules {
            anyhow::ensure!(
                !rule.value.trim().is_empty()
                    && rule.value.len() <= 4096
                    && !rule.value.contains('\0'),
                "process rule requires a nonempty value of at most 4096 bytes"
            );
            if rule.matcher == Matcher::ProcessPath {
                anyhow::ensure!(rule.value.starts_with('/'), "process path must be absolute");
            }
        }
        Ok(())
    }

    /// Return the selected policy and a stable explanation of the winning rule.
    pub fn decide(&self, process: &ProcessIdentity) -> (Policy, String) {
        for rule in self.rules.iter().filter(|rule| rule.enabled) {
            let observed = match rule.matcher {
                Matcher::ProcessName => &process.name,
                Matcher::ProcessPath => &process.path,
            };
            if observed.as_deref() == Some(rule.value.as_str()) {
                return (
                    rule.policy,
                    format!(
                        "{}: {}",
                        match rule.matcher {
                            Matcher::ProcessName => "PROCESS-NAME",
                            Matcher::ProcessPath => "PROCESS-PATH",
                        },
                        rule.value
                    ),
                );
            }
        }
        (self.default_policy, "FINAL".into())
    }
}

/// Rule tests cover precedence, disabled entries, and unidentified processes.
#[cfg(test)]
mod tests {
    use super::*;

    /// First enabled matches win and unknown identities always follow FINAL.
    #[test]
    fn ordered_process_matching() {
        let routing: Routing = serde_json::from_value(serde_json::json!({
            "default_policy": "reject", "rules": [
                {"matcher":"process_name", "value":"curl", "policy":"reject", "enabled":false},
                {"matcher":"process_path", "value":"/usr/bin/curl", "policy":"direct", "enabled":true},
                {"matcher":"process_name", "value":"curl", "policy":"proxy", "enabled":true}
            ]
        })).unwrap();
        routing.validate().unwrap();
        let mut process = ProcessIdentity {
            pid: Some(1),
            name: Some("curl".into()),
            path: Some("/usr/bin/curl".into()),
        };
        assert_eq!(routing.decide(&process).0, Policy::Direct);
        process.path = None;
        assert_eq!(routing.decide(&process).0, Policy::Proxy);
        assert_eq!(
            routing.decide(&ProcessIdentity::default()),
            (Policy::Reject, "FINAL".into())
        );
    }

    /// Invalid process rules fail instead of becoming silent catch-all entries.
    #[test]
    fn validates_rules() {
        for value in ["", "relative/path", " /usr/bin/curl"] {
            let routing = Routing {
                rules: vec![Rule {
                    matcher: Matcher::ProcessPath,
                    value: value.into(),
                    policy: Policy::Direct,
                    enabled: true,
                }],
                ..Routing::default()
            };
            assert!(routing.validate().is_err());
        }
    }
}
