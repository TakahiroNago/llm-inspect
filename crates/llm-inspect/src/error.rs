/// Errors returned while building an [`Inspector`](crate::Inspector) or an
/// [`OutputValidator`](crate::OutputValidator).
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// A rule's regular expression failed to compile.
    #[error("invalid pattern in rule `{id}`: {source}")]
    InvalidPattern {
        /// The rule id.
        id: String,
        /// The underlying regex error.
        #[source]
        source: Box<regex::Error>,
    },
    /// Two rules share the same id.
    #[error("duplicate rule id `{0}`")]
    DuplicateRuleId(String),
    /// A rule has an empty id.
    #[error("rule at index {0} has an empty id")]
    EmptyRuleId(usize),
    /// The TOML rule file could not be parsed.
    #[error("failed to parse rules: {0}")]
    RulesParse(#[from] toml::de::Error),
    /// The JSON Schema could not be compiled.
    #[error("invalid JSON schema: {0}")]
    InvalidSchema(String),
    /// An allow-list pointer is malformed.
    #[error("invalid allow-list pointer `{0}`: must start with '/'")]
    InvalidPointer(String),
}
