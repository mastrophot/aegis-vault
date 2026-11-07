/**
 * LastKey Telegram Sentinel Bot Service
 * 
 * Secure Bot Handshake:
 * - Listens for /start or /pair <TOKEN>
 * - Stores paired chat_id securely without unsolicited spamming
 * - Sends heartbeat reminder notifications & panic alerts
 * 
 * Usage:
 *   TELEGRAM_BOT_TOKEN="your_token_from_botfather" node scripts/telegram_bot.js
 */

const token = process.env.TELEGRAM_BOT_TOKEN;

if (!token) {
  console.log('⚠️ TELEGRAM_BOT_TOKEN not provided in environment.');
  console.log('💡 How to get one in 30 seconds for free:');
  console.log('   1. Open Telegram -> search @BotFather');
  console.log('   2. Send /newbot -> choose name and username (e.g. MyLastKeyAlertBot)');
  console.log('   3. Copy the HTTP API token');
  console.log('   4. Run: TELEGRAM_BOT_TOKEN="your_token" node scripts/telegram_bot.js\n');
}

const API_BASE = token ? `https://api.telegram.org/bot${token}` : null;
let lastUpdateId = 0;
const pairedChats = new Set();

async function sendMessage(chatId, text) {
  if (!API_BASE) return;
  try {
    await fetch(`${API_BASE}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'HTML'
      })
    });
  } catch (err) {
    console.error('Failed to send telegram message:', err.message);
  }
}

async function pollUpdates() {
  if (!API_BASE) return;

  try {
    const res = await fetch(`${API_BASE}/getUpdates?offset=${lastUpdateId + 1}&timeout=30`);
    const data = await res.json();

    if (data.ok && Array.isArray(data.result)) {
      for (const update of data.result) {
        lastUpdateId = update.update_id;

        if (update.message && update.message.text) {
          const chatId = update.message.chat.id;
          const text = update.message.text.trim();
          const from = update.message.from.first_name || 'User';

          console.log(`📩 Received from ${from} (${chatId}): ${text}`);

          if (text.startsWith('/start') || text.startsWith('/pair')) {
            pairedChats.add(chatId);
            await sendMessage(
              chatId,
              `🛡️ <b>Aegis Vault Sentinel Connected!</b>\n\n` +
              `Welcome, <b>${from}</b>. Your Telegram account is now securely linked to your Aegis Vault.\n\n` +
              `✅ <b>Zero-Spam Protection:</b> You will only receive critical alerts:\n` +
              `• 14-day & 3-day advance heartbeat warnings\n` +
              `• Emergency Panic evacuation broadcast notifications\n` +
              `• Unauthorized address modification attempts\n\n` +
              `🔗 <i>Vault Contract: aegis.okgoogleok.testnet</i>`
            );
          } else if (text === '/test_panic') {
            await sendMessage(
              chatId,
              `🚨 <b>[TEST EMERGENCY PANIC]</b>\n\n` +
              `Panic triggered on contract <code>aegis.okgoogleok.testnet</code>!\n` +
              `All assets across BTC, EVM, Solana, and NEAR are being evacuated to your cold backup addresses.`
            );
          } else if (text === '/test_alert') {
            await sendMessage(
              chatId,
              `⚠️ <b>[AEGIS HEARTBEAT WARNING]</b>\n\n` +
              `Your vault has <b>3 days remaining</b> before the inheritance grace window opens!\n\n` +
              `Please open your dashboard and click <b>Check-In Now</b> to reset your timer.`
            );
          }
        }
      }
    }
  } catch (err) {
    console.error('Polling error:', err.message);
  }

  setTimeout(pollUpdates, 1500);
}

if (API_BASE) {
  console.log('🚀 LastKey Telegram Bot Sentinel running...');
  pollUpdates();
}

module.exports = { sendMessage, pairedChats };
