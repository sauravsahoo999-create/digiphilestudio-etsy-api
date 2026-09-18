const express = require("express");
const crypto = require("crypto");

const app = express();
app.set("trust proxy", 1);
app.use(express.json());

const PORT = process.env.PORT || 3000;

const ETSY_CLIENT_ID = process.env.ETSY_CLIENT_ID;
const ETSY_SHARED_SECRET = process.env.ETSY_SHARED_SECRET;
const CONNECTOR_SECRET = process.env.CONNECTOR_SECRET;

const ETSY_AUTHORIZE_URL = "https://www.etsy.com/oauth/connect";
const ETSY_TOKEN_URL = "https://api.etsy.com/v3/public/oauth/token";
const ETSY_API_BASE = "https://api.etsy.com/v3/application";

const SCOPES = [
  "shops_r",
  "listings_r",
  "transactions_r"
].join(" ");

let tokenData = null;
const oauthStates = new Map();

function baseUrl(req) {
  return process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
}

function requireConfig() {
  if (!ETSY_CLIENT_ID || !ETSY_SHARED_SECRET) {
    throw new Error("ETSY_CLIENT_ID and ETSY_SHARED_SECRET are not configured.");
  }
}

function createPkceVerifier() {
  return crypto.randomBytes(48).toString("base64url");
}

function createPkceChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
}

function createState() {
  return crypto.randomBytes(32).toString("hex");
}

async function exchangeAuthorizationCode(code, verifier, redirectUri) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: ETSY_CLIENT_ID,
    redirect_uri: redirectUri,
    code,
    code_verifier: verifier
  });

  const response = await fetch(ETSY_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(
      `Etsy token exchange failed: ${JSON.stringify(data)}`
    );
  }

  return data;
}

async function refreshAccessToken() {
  if (!tokenData?.refresh_token) {
    throw new Error("No Etsy refresh token is available. Authenticate again.");
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: ETSY_CLIENT_ID,
    refresh_token: tokenData.refresh_token
  });

  const response = await fetch(ETSY_TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body
  });

  const data = await response.json();

  if (!response.ok) {
    tokenData = null;
    throw new Error(
      `Etsy token refresh failed: ${JSON.stringify(data)}`
    );
  }

  tokenData = {
    ...data,
    expires_at: Date.now() + (data.expires_in || 3600) * 1000,
    user_id: String(data.access_token || "").split(".")[0]
  };

  return tokenData.access_token;
}

async function getAccessToken() {
  if (!tokenData?.access_token) {
    throw new Error("Etsy is not connected. Open /oauth/start first.");
  }

  if (Date.now() >= tokenData.expires_at - 60_000) {
    return refreshAccessToken();
  }

  return tokenData.access_token;
}

async function etsyRequest(path, options = {}) {
  requireConfig();

  const accessToken = await getAccessToken();

  const response = await fetch(`${ETSY_API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.headers || {}),
      "x-api-key": `${ETSY_CLIENT_ID}:${ETSY_SHARED_SECRET}`,
      "Authorization": `Bearer ${accessToken}`,
      "Accept": "application/json"
    }
  });

  const text = await response.text();

  let data;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { raw: text };
  }

  if (!response.ok) {
    throw new Error(
      `Etsy API ${response.status}: ${JSON.stringify(data)}`
    );
  }

  return data;
}

async function getCurrentUser() {
  return etsyRequest("/users/me");
}

async function getCurrentShop() {
  const user = await getCurrentUser();

  const shops = await etsyRequest(
    `/users/${encodeURIComponent(user.user_id)}/shops`
  );

  const shop =
    Array.isArray(shops?.results)
      ? shops.results[0]
      : shops;

  if (!shop?.shop_id) {
    throw new Error("No Etsy shop was found for this account.");
  }

  return { user, shop };
}

async function getAllPages(path, extraParams = {}) {
  const allResults = [];
  let offset = 0;
  const limit = 100;

  while (true) {
    const params = new URLSearchParams({
      ...extraParams,
      limit: String(limit),
      offset: String(offset)
    });

    const data = await etsyRequest(`${path}?${params.toString()}`);

    const results = Array.isArray(data?.results)
      ? data.results
      : [];

    allResults.push(...results);

    const count = Number(data?.count || 0);

    if (
      results.length === 0 ||
      allResults.length >= count ||
      results.length < limit
    ) {
      break;
    }

    offset += limit;

    if (offset > 12000) {
      break;
    }
  }

  return {
    count: allResults.length,
    results: allResults
  };
}

/* -------------------------------------------------------
   BASIC STATUS
------------------------------------------------------- */

app.get("/", (req, res) => {
  res.json({
    service: "DigiPhileStudio Etsy API",
    status: "online",
    etsy_connected: Boolean(tokenData?.access_token),
    oauth_start: `${baseUrl(req)}/oauth/start`
  });
});

/* -------------------------------------------------------
   ETSY OAUTH
------------------------------------------------------- */

app.get("/oauth/start", (req, res) => {
  try {
    requireConfig();

    const verifier = createPkceVerifier();
    const challenge = createPkceChallenge(verifier);
    const state = createState();

    oauthStates.set(state, {
      verifier,
      createdAt: Date.now()
    });

    const redirectUri = `${baseUrl(req)}/oauth/callback`;

    const url = new URL(ETSY_AUTHORIZE_URL);

    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", ETSY_CLIENT_ID);
    url.searchParams.set("redirect_uri", redirectUri);
    url.searchParams.set("scope", SCOPES);
    url.searchParams.set("state", state);
    url.searchParams.set("code_challenge", challenge);
    url.searchParams.set("code_challenge_method", "S256");

    res.redirect(url.toString());
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

app.get("/oauth/callback", async (req, res) => {
  try {
    requireConfig();

    const { code, state, error, error_description } = req.query;

    if (error) {
      return res.status(400).send(`
        <h2>Etsy authorization failed</h2>
        <p>${error_description || error}</p>
      `);
    }

    if (!code || !state) {
      return res.status(400).send("Missing Etsy authorization code or state.");
    }

    const stored = oauthStates.get(state);

    if (!stored) {
      return res.status(400).send("Invalid or expired OAuth state.");
    }

    oauthStates.delete(state);

    if (Date.now() - stored.createdAt > 10 * 60 * 1000) {
      return res.status(400).send("OAuth request expired. Please try again.");
    }

    const redirectUri = `${baseUrl(req)}/oauth/callback`;

    const newTokenData = await exchangeAuthorizationCode(
      code,
      stored.verifier,
      redirectUri
    );

    tokenData = {
      ...newTokenData,
      expires_at:
        Date.now() + (newTokenData.expires_in || 3600) * 1000,
      user_id: String(
        newTokenData.access_token || ""
      ).split(".")[0]
    };

    res.send(`
      <html>
        <head>
          <title>Etsy Connected</title>
        </head>
        <body style="font-family: Arial; padding: 40px;">
          <h2>✅ Etsy connected successfully</h2>
          <p>Your Etsy account has authorized this application.</p>
          <p>You can now use the protected API endpoints.</p>
          <p><a href="/">Open service status</a></p>
        </body>
      </html>
    `);
  } catch (error) {
    res.status(500).send(`
      <h2>Etsy connection failed</h2>
      <pre>${error.message}</pre>
    `);
  }
});

/* -------------------------------------------------------
   API SECURITY
------------------------------------------------------- */

function authenticateConnector(req, res, next) {
  if (!CONNECTOR_SECRET) {
    return res.status(500).json({
      error: "CONNECTOR_SECRET is not configured."
    });
  }

  const supplied = req.get("Authorization") || "";

  if (supplied !== `Bearer ${CONNECTOR_SECRET}`) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  next();
}

/* -------------------------------------------------------
   PRIVATE ETSY DATA
------------------------------------------------------- */

app.get("/api/me", authenticateConnector, async (req, res) => {
  try {
    const user = await getCurrentUser();
    res.json(user);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/shop", authenticateConnector, async (req, res) => {
  try {
    const { user, shop } = await getCurrentShop();

    const fullShop = await etsyRequest(
      `/shops/${shop.shop_id}`
    );

    res.json({
      user,
      shop: fullShop
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/listings", authenticateConnector, async (req, res) => {
  try {
    const { shop } = await getCurrentShop();

    const state = req.query.state || "active";

    const allowedStates = [
      "active",
      "inactive",
      "sold_out",
      "draft",
      "expired"
    ];

    if (!allowedStates.includes(state)) {
      return res.status(400).json({
        error: "Invalid state",
        allowedStates
      });
    }

    const data = await getAllPages(
      `/shops/${shop.shop_id}/listings`,
      {
        state,
        includes: "personalization"
      }
    );

    res.json({
      shop_id: shop.shop_id,
      state,
      ...data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/receipts", authenticateConnector, async (req, res) => {
  try {
    const { shop } = await getCurrentShop();

    const data = await getAllPages(
      `/shops/${shop.shop_id}/receipts`
    );

    res.json({
      shop_id: shop.shop_id,
      ...data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/transactions", authenticateConnector, async (req, res) => {
  try {
    const { shop } = await getCurrentShop();

    const data = await getAllPages(
      `/shops/${shop.shop_id}/transactions`
    );

    res.json({
      shop_id: shop.shop_id,
      ...data
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/* -------------------------------------------------------
   EXPORT EVERYTHING AVAILABLE THROUGH THIS API
------------------------------------------------------- */

app.get("/api/export", authenticateConnector, async (req, res) => {
  try {
    const { user, shop } = await getCurrentShop();

    const listings = {};

    for (const state of [
      "active",
      "inactive",
      "sold_out",
      "draft",
      "expired"
    ]) {
      listings[state] = await getAllPages(
        `/shops/${shop.shop_id}/listings`,
        {
          state,
          includes: "personalization"
        }
      );
    }

    const receipts = await getAllPages(
      `/shops/${shop.shop_id}/receipts`
    );

    const transactions = await getAllPages(
      `/shops/${shop.shop_id}/transactions`
    );

    res.json({
      exported_at: new Date().toISOString(),
      user,
      shop,
      listings,
      receipts,
      transactions
    });
  } catch (error) {
    res.status(500).json({
      error: error.message
    });
  }
});

app.listen(PORT, () => {
  console.log(`DigiPhileStudio Etsy API running on port ${PORT}`);
});
