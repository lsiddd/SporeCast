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
