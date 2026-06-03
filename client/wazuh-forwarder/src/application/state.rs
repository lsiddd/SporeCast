//! Persistent runtime state management.

use anyhow::{Context, Result};
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};

use crate::domain::behavioral::AlertHistory;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct State {
    pub inode: Option<u64>,
    pub offset: u64,
    #[serde(skip)]
    pub alert_history: AlertHistory,
}

pub struct StateManager {
    state_file: String,
    pub(crate) state: State,
}

impl StateManager {
    pub fn new(state_file: &str) -> Self {
        debug!("Creating new StateManager for file: {}", state_file);
        let state = State::default();
        Self {
            state_file: state_file.to_string(),
            state,
        }
    }

    pub fn load(&mut self) -> Result<()> {
        info!("Attempting to load state from: {}", self.state_file);
        if !Path::new(&self.state_file).exists() {
            info!(
                "State file not found at {}. Using default state for first run.",
                self.state_file
            );
            return Ok(());
        }
        let contents = fs::read_to_string(&self.state_file)
            .with_context(|| format!("Failed to read state file {}", self.state_file))?;
        self.state = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse state file {}", self.state_file))?;
        info!(
            "Successfully loaded state from {}. Behavioral analysis history will start fresh.",
            self.state_file
        );
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        debug!("Attempting to save state to: {}", self.state_file);
        let serialized =
            serde_json::to_string(&self.state).context("Failed to serialize state to JSON")?;
        if let Some(parent) = Path::new(&self.state_file).parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "Failed to create parent directory for state file: {:?}",
                    parent
                )
            })?;
            debug!(
                "Ensured parent directory for state file exists: {:?}",
                parent
            );
        }
        fs::write(&self.state_file, serialized)
            .with_context(|| format!("Failed to write state to file {}", self.state_file))?;
        debug!("Successfully saved state (excluding behavioral history).");
        Ok(())
    }

    pub(crate) fn merge_worker_state(&mut self, worker_state: &AlertHistory) {
        debug!("Merging worker state into main state manager");
        self.state.alert_history.merge(worker_state.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_state_file(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after epoch")
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "wazuh_forwarder_{name}_{}_{}.json",
                std::process::id(),
                nanos
            ))
            .display()
            .to_string()
    }

    #[test]
    fn save_then_load_preserves_file_offset_without_behavioral_history() {
        let state_file = unique_state_file("state_round_trip");
        let mut manager = StateManager::new(&state_file);
        manager.state.inode = Some(42);
        manager.state.offset = 4096;
        manager
            .state
            .alert_history
            .update(&json!({ "source_address": "203.0.113.10" }));

        manager.save().expect("state should save");

        let saved = fs::read_to_string(&state_file).expect("saved state file should exist");
        assert!(!saved.contains("alert_history"));

        let mut reloaded = StateManager::new(&state_file);
        reloaded.load().expect("state should load");

        assert_eq!(reloaded.state.inode, Some(42));
        assert_eq!(reloaded.state.offset, 4096);
        assert_eq!(
            reloaded.state.alert_history.src_ips.peek("203.0.113.10"),
            None
        );

        let _ = fs::remove_file(state_file);
    }

    #[test]
    fn corrupt_state_file_returns_parse_error() {
        let state_file = unique_state_file("corrupt_state");
        fs::write(&state_file, "{not valid json").expect("corrupt state should be written");
        let mut manager = StateManager::new(&state_file);

        let error = manager
            .load()
            .expect_err("corrupt JSON should fail to load");

        assert!(
            error.to_string().contains("Failed to parse state file"),
            "unexpected error: {error}"
        );

        let _ = fs::remove_file(state_file);
    }

    #[test]
    fn missing_state_file_keeps_default_state() {
        let state_file = unique_state_file("missing_state");
        let mut manager = StateManager::new(&state_file);

        manager
            .load()
            .expect("missing state file should be accepted");

        assert_eq!(manager.state.inode, None);
        assert_eq!(manager.state.offset, 0);
        assert_eq!(manager.state.alert_history.src_ips.len(), 0);
    }

    #[test]
    fn save_creates_missing_parent_directories() {
        let state_file = std::env::temp_dir()
            .join(format!(
                "wazuh_forwarder_nested_{}_{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("system clock should be after epoch")
                    .as_nanos()
            ))
            .join("state")
            .join("state.json");
        let state_file = state_file.display().to_string();
        let mut manager = StateManager::new(&state_file);
        manager.state.inode = Some(7);
        manager.state.offset = 128;

        manager
            .save()
            .expect("state save should create parent directories");

        let saved = fs::read_to_string(&state_file).expect("state file should exist");
        assert!(saved.contains("\"inode\":7"));
        assert!(saved.contains("\"offset\":128"));

        if let Some(root) = Path::new(&state_file).ancestors().nth(2) {
            let _ = fs::remove_dir_all(root);
        }
    }
}
