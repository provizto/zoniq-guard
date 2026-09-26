export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method Not Allowed' });

  try {
    const { planType, txHash, network, buyerWallet, referralCode, commissionAmount } = req.body || {};

    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;

    if (!botToken || !chatId) {
      return res.status(500).json({ success: false, error: 'Telegram credentials missing in Vercel' });
    }

    const refDetails = referralCode 
      ? `\n🏷️ <b>Referral:</b> ${referralCode}\n💵 <b>Commission:</b> ${commissionAmount || '-'}`
      : '\n🏷️ <b>Referral:</b> None';

    const message = `💰 <b>PAYMENT CONFIRMED</b>\n\n` +
      `📦 <b>Plan:</b> ${planType ? planType.toUpperCase() : 'N/A'}\n` +
      `🌐 <b>Network:</b> ${network || 'N/A'}\n` +
      `👤 <b>Wallet:</b> <code>${buyerWallet || 'N/A'}</code>${refDetails}\n` +
      `🔗 <b>Tx:</b> <code>${txHash || 'N/A'}</code>`;

    const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, text: message, parse_mode: 'HTML' })
    });

    const result = await tgRes.json();
    return res.status(200).json({ success: result.ok });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
}