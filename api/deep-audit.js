// D:\zoniq-guard\api\deep-audit.js

export default async function handler(req, res) {
  // Atur Header CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
  );

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  try {
    const { code, chain } = req.body || {};

    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'GEMINI_API_KEY is not configured on Vercel' });
    }

    // Panggil API Gemini Langsung
    const prompt = `You are a Tier-1 Smart Contract Security Auditor specialized in ${chain || 'evm'}.
Analyze the following source code and return ONLY valid JSON:
{
  "securityScore": number (0-100),
  "findings": [
    {
      "title": string,
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "description": string,
      "remediation": string
    }
  ]
}

Source Code:
${code}`;

    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${apiKey}`;
    
    const response = await fetch(geminiUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
        generationConfig: { responseMimeType: "application/json" }
      })
    });

    const aiData = await response.json();
    const rawText = aiData?.candidates?.[0]?.content?.parts?.[0]?.text || '{}';
    const parsedData = JSON.parse(rawText);

    return res.status(200).json({
      success: true,
      data: {
        securityScore: parsedData.securityScore || 85,
        findings: parsedData.findings || []
      }
    });

  } catch (error) {
    console.error("AI Audit Handler Error:", error);
    return res.status(500).json({ 
      success: false, 
      error: error.message || 'Internal AI Engine Error' 
    });
  }
}