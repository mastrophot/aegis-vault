/**
 * Aegis Zero-Metadata Telegram Push Bot Helper
 *
 * Security Rules:
 * - Never includes wallet addresses, account IDs, dates, tx hashes, or chain names in messages
 * - Never passes destructive offset to getUpdates so stateless /start v1_<sha256> tags remain queryable
 */

const token = process.env.TELEGRAM_BOT_TOKEN;
const API_BASE = token ? `https://api.telegram.org/bot${token}` : null;
const processedUpdateIds = new Set();

const ZERO_METADATA_MESSAGES = {
  test: '🛡 Aegis Bunker: Notification channel connected and active.',
  reminder: '⏳ Aegis Bunker: Check-in window is nearing expiration. Perform a check-in to keep the bunker armed.',
  grace: '⚠️ Aegis Bunker: Primary timer expired. Grace buffer is now active.',
  panic: '🚨 Aegis Bunker: Emergency evacuation completed.',
  inheritance: '🔒 Aegis Bunker: Inheritance protocol completed.'
};

async function sendMessage(chatId, text) {
  if (!API_BASE) return;
  try {
    await fetch(`${API_BASE}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        disable_web_page_preview: true
      })
    });
  } catch (err) {
    console.error('Failed to send telegram message:', err.message);
  }
}

async function pollUpdates() {
  if (!API_BASE) return;

  try {
    const res = await fetch(`${API_BASE}/getUpdates?limit=100`);
    const data = await res.json();

    if (data.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        if (processedUpdateIds.has(update.update_id)) continue;
        processedUpdateIds.add(update.update_id);

        if (update.message && update.message.text) {
          const chatId = update.message.chat.id;
          const text = update.message.text.trim();

          if (text.startsWith('/start')) {
            await sendMessage(chatId, ZERO_METADATA_MESSAGES.test);
          } else if (text === '/test_panic') {
            await sendMessage(chatId, ZERO_METADATA_MESSAGES.panic);
          } else if (text === '/test_inheritance') {
            await sendMessage(chatId, ZERO_METADATA_MESSAGES.inheritance);
          } else if (text === '/test_alert') {
            await sendMessage(chatId, ZERO_METADATA_MESSAGES.reminder);
          }
        }
      }
    }
  } catch (err) {
    console.error('Polling error:', err.message);
  }

  setTimeout(pollUpdates, 3000);
}

if (API_BASE && require.main === module) {
  pollUpdates();
}

module.exports = { sendMessage, ZERO_METADATA_MESSAGES };
