//! Process-wide, secret-safe stderr logging configuration.

use std::env::VarError;

use tracing_subscriber::filter::ParseError;
use tracing_subscriber::EnvFilter;

/// Environment variable selecting the process log renderer.
pub const LOG_FORMAT_ENV: &str = "TUNNELPROXY_LOG_FORMAT";
const DEFAULT_LOG_FILTER: &str = "info";

/// Supported process log renderers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessLogFormat {
    /// Human-readable compact events.
    Text,
    /// One JSON object per event, suitable for log collectors.
    Json,
}

impl ProcessLogFormat {
    fn parse(value: Option<&str>) -> Result<Self, ProcessLoggingConfigError> {
        match value {
            None | Some("text") => Ok(Self::Text),
            Some("json") => Ok(Self::Json),
            Some(_) => Err(ProcessLoggingConfigError::InvalidFormat),
        }
    }
}

/// Invalid logging configuration or failed process-wide subscriber setup.
#[derive(Debug)]
pub enum ProcessLoggingConfigError {
    NonUnicodeFormat,
    InvalidFormat,
    NonUnicodeFilter,
    InvalidFilter(ParseError),
    SubscriberAlreadySet,
}

impl std::fmt::Display for ProcessLoggingConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonUnicodeFormat => {
                write!(formatter, "{LOG_FORMAT_ENV} must contain Unicode text")
            }
            Self::InvalidFormat => {
                write!(formatter, "{LOG_FORMAT_ENV} must be `text` or `json`")
            }
            Self::NonUnicodeFilter => formatter.write_str("RUST_LOG must contain Unicode text"),
            Self::InvalidFilter(_) => formatter.write_str("RUST_LOG contains an invalid filter"),
            Self::SubscriberAlreadySet => {
                formatter.write_str("the process logging subscriber is already configured")
            }
        }
    }
}

impl std::error::Error for ProcessLoggingConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidFilter(error) => Some(error),
            _ => None,
        }
    }
}

fn read_env(name: &'static str) -> Result<Option<String>, VarError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(error @ VarError::NotUnicode(_)) => Err(error),
    }
}

fn parse_filter(value: Option<&str>) -> Result<EnvFilter, ProcessLoggingConfigError> {
    EnvFilter::try_new(value.unwrap_or(DEFAULT_LOG_FILTER))
        .map_err(ProcessLoggingConfigError::InvalidFilter)
}

/// Installs the process-wide subscriber and returns the selected renderer.
///
/// Both renderers write only to stderr. Callers should retain stdout for stable
/// command output and help text.
pub fn init_process_logging() -> Result<ProcessLogFormat, ProcessLoggingConfigError> {
    let format = ProcessLogFormat::parse(
        read_env(LOG_FORMAT_ENV)
            .map_err(|_| ProcessLoggingConfigError::NonUnicodeFormat)?
            .as_deref(),
    )?;
    let filter = parse_filter(
        read_env("RUST_LOG")
            .map_err(|_| ProcessLoggingConfigError::NonUnicodeFilter)?
            .as_deref(),
    )?;

    let result = match format {
        ProcessLogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init(),
        ProcessLogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_ansi(false)
            .with_target(true)
            .flatten_event(false)
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .try_init(),
    };
    result.map_err(|_| ProcessLoggingConfigError::SubscriberAlreadySet)?;
    Ok(format)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_defaults_to_text_and_accepts_documented_values() {
        assert_eq!(
            ProcessLogFormat::parse(None).unwrap(),
            ProcessLogFormat::Text
        );
        assert_eq!(
            ProcessLogFormat::parse(Some("text")).unwrap(),
            ProcessLogFormat::Text
        );
        assert_eq!(
            ProcessLogFormat::parse(Some("json")).unwrap(),
            ProcessLogFormat::Json
        );
    }

    #[test]
    fn format_rejects_empty_unknown_and_case_changed_values() {
        for value in ["", "JSON", "pretty"] {
            assert!(matches!(
                ProcessLogFormat::parse(Some(value)),
                Err(ProcessLoggingConfigError::InvalidFormat)
            ));
        }
    }

    #[test]
    fn filter_accepts_directives_and_rejects_invalid_syntax() {
        assert!(parse_filter(None).is_ok());
        assert!(parse_filter(Some("warn,tunnelproxy_edge=debug")).is_ok());
        assert!(matches!(
            parse_filter(Some("tunnelproxy_edge[")),
            Err(ProcessLoggingConfigError::InvalidFilter(_))
        ));
    }

    #[test]
    fn configuration_errors_do_not_echo_filter_contents() {
        let error = parse_filter(Some("secret-token[")).unwrap_err().to_string();
        assert!(!error.contains("secret-token"));
    }
}
