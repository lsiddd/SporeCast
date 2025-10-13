use log::{debug, error, warn};
use reqwest::Client;

use crate::config::*;

// ==============================================================================
// --- Telegram Notifications ---
// Handles sending messages to a Telegram bot.
// ==============================================================================
pub async fn send_telegram_message(message: String) {
    // Changed to take String to own the message
    if !ENABLE_TELEGRAM {
        debug!(
            "Telegram notifications are disabled. Skipping message: {}",
            message
        );
        return;
    }
    if TELEGRAM_TOKEN == "YOUR_TELEGRAM_BOT_TOKEN" || TELEGRAM_CHAT_ID == "YOUR_TELEGRAM_CHAT_ID" {
        warn!(
            "Telegram token or chat ID is not configured. Cannot send message: {}",
            message
        );
        return;
    }

    debug!("Attempting to send Telegram message.");
    let client = Client::new();
    let url = format!("https://api.telegram.org/bot{}/sendMessage", TELEGRAM_TOKEN);
    let params = [
        ("chat_id", TELEGRAM_CHAT_ID),
        ("text", &format!("[Fortigate-Forwarder]\n{}", message)),
        ("parse_mode", "Markdown"), // Allows basic formatting in Telegram messages.
    ];
    if let Err(e) = client.post(&url).form(&params).send().await {
        error!(
            "Failed to send Telegram message: {}. Check token, chat ID, and network connectivity.",
            e
        );
    } else {
        debug!("Telegram message sent successfully.");
    }
}