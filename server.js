const express = require("express");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);

app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const PORT = process.env.PORT || 3000;

const ETSY_CLIENT_ID = process.env.ETSY_CLIENT_ID;
const ETSY_SHARED_SECRET = process.env.ETSY_SHARED_SECRET;
const CONNECTOR_SECRET = process.env.CONNECTOR_SECRET;
const ETSY_REFRESH_TOKEN = process.env.ETSY_REFRESH_TOKEN;

const ETSY_AUTHORIZE_URL =
  "https://www.etsy.com/oauth/connect";

const ETSY_TOKEN_URL =
  "https://api.etsy.com/v3/public/oauth/token";

const ETSY_API_BASE =
  "https://api.etsy.com/v3/application";

/*
  We only request permissions actually needed
  for the shop-data export.

  shops_r        = read shop information
  listings_r     = read listings
  transactions_r = read sales / transaction data
*/
const SCOPES = [
  "shops_r",
  "listings_r",
  "transactions_r"
].join(" ");

let tokenData = null;

const oauthStates = new Map();

/* =========================================================
   HELPERS
========================================================= */

function baseUrl(req) {
  return (
    process.env.PUBLIC_BASE_URL ||
    `${req.protocol}://${req.get("host")}`
  );
}

function requireConfig() {
  if (!ETSY_CLIENT_ID) {
    throw new Error(
      "ETSY_CLIENT_ID is not configured."
    );
  }

  if (!ETSY_SHARED_SECRET) {
    throw new Error(
      "ETSY_SHARED_SECRET is not configured."
    );
  }
}

function createPkceVerifier() {
  return crypto
    .randomBytes(48)
    .toString("base64url");
}

function createPkceChallenge(verifier) {
  return crypto
    .createHash("sha256")
    .update(verifier)
    .digest("base64url");
}

function createState() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

/* =========================================================
   OAUTH TOKEN EXCHANGE
========================================================= */

async function exchangeAuthorizationCode(
  code,
  verifier,
  redirectUri
) {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: ETSY_CLIENT_ID,
    redirect_uri: redirectUri,
    code: code,
    code_verifier: verifier
  });

  const response = await fetch(
    ETSY_TOKEN_URL,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body
    }
  );

  const data =
    await response.json();

  if (!response.ok) {
    throw new Error(
      `Etsy token exchange failed: ${JSON.stringify(data)}`
    );
  }

  return data;
}

/* =========================================================
   REFRESH ACCESS TOKEN
========================================================= */

async function refreshAccessToken(
  refreshToken
) {
  if (!refreshToken) {
    throw new Error(
      "No Etsy refresh token is available."
    );
  }

  const body = new URLSearchParams({
    grant_type: "refresh_token",
    client_id: ETSY_CLIENT_ID,
    refresh_token: refreshToken
  });

  const response = await fetch(
    ETSY_TOKEN_URL,
    {
      method: "POST",

      headers: {
        "Content-Type":
          "application/x-www-form-urlencoded"
      },

      body
    }
  );

  const data =
    await response.json();

  if (!response.ok) {
    tokenData = null;

    throw new Error(
      `Etsy token refresh failed: ${JSON.stringify(data)}`
    );
  }

  tokenData = {
    ...data,

    expires_at:
      Date.now() +
      (data.expires_in || 3600) *
        1000,

    refresh_token:
      data.refresh_token ||
      refreshToken
  };

  return tokenData.access_token;
}

/* =========================================================
   GET ACCESS TOKEN
========================================================= */

async function getAccessToken() {

  /*
    Use current in-memory access token when possible.
  */
  if (
    tokenData?.access_token &&
    tokenData?.expires_at &&
    Date.now() <
      tokenData.expires_at - 60000
  ) {
    return tokenData.access_token;
  }

  /*
    Otherwise refresh using the latest refresh token
    or the token stored in Render.
  */
  const refreshToken =
    tokenData?.refresh_token ||
    ETSY_REFRESH_TOKEN;

  if (refreshToken) {
    return refreshAccessToken(
      refreshToken
    );
  }

  throw new Error(
    "Etsy is not connected. Open /oauth/start first."
  );
}

/* =========================================================
   ETSY REQUEST
========================================================= */

async function etsyRequest(
  path,
  options = {}
) {
  requireConfig();

  const accessToken =
    await getAccessToken();

  const response = await fetch(
    `${ETSY_API_BASE}${path}`,
    {
      ...options,

      headers: {
        ...(options.headers || {}),

        "x-api-key":
          `${ETSY_CLIENT_ID}:${ETSY_SHARED_SECRET}`,

        Authorization:
          `Bearer ${accessToken}`,

        Accept:
          "application/json"
      }
    }
  );

  const text =
    await response.text();

  let data;

  try {
    data =
      text
        ? JSON.parse(text)
        : {};
  } catch {
    data = {
      raw: text
    };
  }

  if (!response.ok) {
    throw new Error(
      `Etsy API ${response.status}: ${JSON.stringify(data)}`
    );
  }

  return data;
}

/* =========================================================
   GET USER ID FROM TOKEN
========================================================= */

function getUserIdFromToken(
  accessToken
) {
  const userId =
    String(accessToken)
      .split(".")[0];

  if (!userId) {
    throw new Error(
      "Could not determine Etsy user ID."
    );
  }

  return userId;
}

/* =========================================================
   CURRENT SHOP
========================================================= */

async function getCurrentShop() {
  const accessToken =
    await getAccessToken();

  const userId =
    getUserIdFromToken(
      accessToken
    );

  /*
    We do NOT call the user-profile endpoint.
    That endpoint needs email_r.

    We only need the user ID to find the shop.
  */
  const shops =
    await etsyRequest(
      `/users/${encodeURIComponent(
        userId
      )}/shops`
    );

  const shop =
    Array.isArray(shops?.results)
      ? shops.results[0]
      : shops;

  if (!shop?.shop_id) {
    throw new Error(
      "No Etsy shop was found for this Etsy account."
    );
  }

  return {
    user: {
      user_id:
        userId
    },

    shop
  };
}

/* =========================================================
   PAGINATION
========================================================= */

async function getAllPages(
  path,
  extraParams = {}
) {
  const allResults = [];

  let offset = 0;

  const limit = 100;

  while (true) {

    const params =
      new URLSearchParams({
        ...extraParams,

        limit:
          String(limit),

        offset:
          String(offset)
      });

    const data =
      await etsyRequest(
        `${path}?${params.toString()}`
      );

    const results =
      Array.isArray(data?.results)
        ? data.results
        : [];

    allResults.push(
      ...results
    );

    const count =
      Number(data?.count || 0);

    if (
      results.length === 0 ||
      allResults.length >= count ||
      results.length < limit
    ) {
      break;
    }

    offset += limit;

    /*
      Safety limit.
    */
    if (offset > 12000) {
      break;
    }
  }

  return {
    count:
      allResults.length,

    results:
      allResults
  };
}

/* =========================================================
   HOME
========================================================= */

app.get(
  "/",
  async (req, res) => {

    let connected = false;

    try {
      await getAccessToken();
      connected = true;
    } catch {
      connected = false;
    }

    res.json({
      service:
        "DigiPhileStudio Etsy API",

      status:
        "online",

      etsy_connected:
        connected,

      oauth_start:
        `${baseUrl(req)}/oauth/start`,

      download_page:
        `${baseUrl(req)}/download`
    });
  }
);

/* =========================================================
   HEALTH
========================================================= */

app.get(
  "/health",
  (req, res) => {

    res.json({
      status:
        "ok"
    });

  }
);

/* =========================================================
   OAUTH START
========================================================= */

app.get(
  "/oauth/start",
  (req, res) => {

    try {

      requireConfig();

      const verifier =
        createPkceVerifier();

      const challenge =
        createPkceChallenge(
          verifier
        );

      const state =
        createState();

      oauthStates.set(
        state,
        {
          verifier,

          createdAt:
            Date.now()
        }
      );

      const redirectUri =
        `${baseUrl(req)}/oauth/callback`;

      const url =
        new URL(
          ETSY_AUTHORIZE_URL
        );

      url.searchParams.set(
        "response_type",
        "code"
      );

      url.searchParams.set(
        "client_id",
        ETSY_CLIENT_ID
      );

      url.searchParams.set(
        "redirect_uri",
        redirectUri
      );

      url.searchParams.set(
        "scope",
        SCOPES
      );

      url.searchParams.set(
        "state",
        state
      );

      url.searchParams.set(
        "code_challenge",
        challenge
      );

      url.searchParams.set(
        "code_challenge_method",
        "S256"
      );

      res.redirect(
        url.toString()
      );

    } catch (error) {

      res.status(500).json({
        error:
          error.message
      });

    }

  }
);

/* =========================================================
   OAUTH CALLBACK
========================================================= */

app.get(
  "/oauth/callback",
  async (req, res) => {

    try {

      requireConfig();

      const {
        code,
        state,
        error,
        error_description
      } = req.query;

      if (error) {

        return res
          .status(400)
          .send(`
            <html>
              <body
                style="
                  font-family:Arial;
                  padding:40px;
                "
              >

                <h2>
                  ❌ Etsy authorization failed
                </h2>

                <p>
                  ${error_description || error}
                </p>

              </body>
            </html>
          `);
      }

      if (!code || !state) {

        return res
          .status(400)
          .send(
            "Missing Etsy authorization code or state."
          );
      }

      const stored =
        oauthStates.get(
          state
        );

      if (!stored) {

        return res
          .status(400)
          .send(
            "Invalid or expired OAuth state."
          );
      }

      oauthStates.delete(
        state
      );

      if (
        Date.now() -
          stored.createdAt >
        10 * 60 * 1000
      ) {

        return res
          .status(400)
          .send(
            "OAuth request expired. Start again."
          );
      }

      const redirectUri =
        `${baseUrl(req)}/oauth/callback`;

      const newTokenData =
        await exchangeAuthorizationCode(
          code,
          stored.verifier,
          redirectUri
        );

      tokenData = {
        ...newTokenData,

        expires_at:
          Date.now() +
          (newTokenData.expires_in || 3600) *
            1000
      };

      const refreshToken =
        newTokenData.refresh_token ||
        "";

      res.send(`
        <html>

          <head>
            <title>
              Etsy Connected
            </title>
          </head>

          <body
            style="
              font-family:Arial;
              padding:40px;
              max-width:900px;
              margin:auto;
            "
          >

            <h2>
              ✅ Etsy connected successfully
            </h2>

            <p>
              Your Etsy account has authorized
              the application.
            </p>

            <h3>
              Save this refresh token in Render
            </h3>

            <p>
              Environment variable:
            </p>

            <p>
              <strong>
                ETSY_REFRESH_TOKEN
              </strong>
            </p>

            <textarea
              readonly
              style="
                width:100%;
                height:110px;
                padding:12px;
                box-sizing:border-box;
                font-family:monospace;
              "
            >${refreshToken}</textarea>

            <p style="color:#a00;">
              Keep this token private.
              Do not publish it or put it in GitHub.
            </p>

            <hr>

            <p>
              After saving the refresh token in Render,
              redeploy the service.
            </p>

            <p>
              Then open:
            </p>

            <p>
              <a href="/download">
                Open Etsy Data Download
              </a>
            </p>

          </body>
        </html>
      `);

    } catch (error) {

      res
        .status(500)
        .send(`
          <html>

            <body
              style="
                font-family:Arial;
                padding:40px;
              "
            >

              <h2>
                ❌ Etsy connection failed
              </h2>

              <pre>
${error.message}
              </pre>

            </body>

          </html>
        `);
    }
  }
);

/* =========================================================
   CONNECTOR SECURITY
========================================================= */

function authenticateConnector(
  req,
  res,
  next
) {

  if (!CONNECTOR_SECRET) {

    return res
      .status(500)
      .json({
        error:
          "CONNECTOR_SECRET is not configured."
      });
  }

  const supplied =
    req.get("Authorization") ||
    "";

  if (
    supplied !==
    `Bearer ${CONNECTOR_SECRET}`
  ) {

    return res
      .status(401)
      .json({
        error:
          "Unauthorized"
      });
  }

  next();
}

/* =========================================================
   SHOP ENDPOINT
========================================================= */

app.get(
  "/api/shop",
  authenticateConnector,
  async (req, res) => {

    try {

      const {
        user,
        shop
      } =
        await getCurrentShop();

      const fullShop =
        await etsyRequest(
          `/shops/${shop.shop_id}`
        );

      res.json({
        user,

        shop:
          fullShop
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   LISTINGS ENDPOINT
========================================================= */

app.get(
  "/api/listings",
  authenticateConnector,
  async (req, res) => {

    try {

      const {
        shop
      } =
        await getCurrentShop();

      const state =
        req.query.state ||
        "active";

      const allowedStates = [
        "active",
        "inactive",
        "sold_out",
        "draft",
        "expired"
      ];

      if (
        !allowedStates.includes(
          state
        )
      ) {

        return res
          .status(400)
          .json({

            error:
              "Invalid listing state.",

            allowedStates
          });
      }

      const data =
        await getAllPages(
          `/shops/${shop.shop_id}/listings`,
          {
            state
          }
        );

      res.json({

        shop_id:
          shop.shop_id,

        state,

        ...data
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   RECEIPTS / ORDERS
========================================================= */

app.get(
  "/api/receipts",
  authenticateConnector,
  async (req, res) => {

    try {

      const {
        shop
      } =
        await getCurrentShop();

      const data =
        await getAllPages(
          `/shops/${shop.shop_id}/receipts`
        );

      res.json({

        shop_id:
          shop.shop_id,

        ...data
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   TRANSACTIONS / SALES
========================================================= */

app.get(
  "/api/transactions",
  authenticateConnector,
  async (req, res) => {

    try {

      const {
        shop
      } =
        await getCurrentShop();

      const data =
        await getAllPages(
          `/shops/${shop.shop_id}/transactions`
        );

      res.json({

        shop_id:
          shop.shop_id,

        ...data
      });

    } catch (error) {

      res
        .status(500)
        .json({
          error:
            error.message
        });
    }
  }
);

/* =========================================================
   COMPLETE EXPORT
========================================================= */

async function createExport() {

  const {
    user,
    shop
  } =
    await getCurrentShop();

  const listings = {};

  for (
    const state of [
      "active",
      "inactive",
      "sold_out",
      "draft",
      "expired"
    ]
  ) {

    listings[state] =
      await getAllPages(
        `/shops/${shop.shop_id}/listings`,
        {
          state
        }
      );
  }

  const transactions =
    await getAllPages(
      `/shops/${shop.shop_id}/transactions`
    );

  let receipts;

  try {

    receipts =
      await getAllPages(
        `/shops/${shop.shop_id}/receipts`
      );

  } catch (error) {

    receipts = {

      count:
        0,

      results:
        [],

      error:
        error.message
    };
  }

  return {

    exported_at:
      new Date().toISOString(),

    user,

    shop,

    listings,

    transactions,

    receipts
  };
}

/* =========================================================
   DOWNLOAD PAGE
========================================================= */

app.get(
  "/download",
  (req, res) => {

    res.send(`

      <html>

        <head>

          <title>
            DigiPhileStudio Etsy Export
          </title>

        </head>

        <body
          style="
            font-family:Arial;
            padding:40px;
            max-width:700px;
            margin:auto;
          "
        >

          <h2>
            📦 DigiPhileStudio Etsy Export
          </h2>

          <p>
            Enter your CONNECTOR_SECRET
            to download your private Etsy shop data.
          </p>

          <form
            method="POST"
            action="/download"
          >

            <label>
              CONNECTOR_SECRET
            </label>

            <br><br>

            <input
              type="password"
              name="secret"
              required

              style="
                width:100%;
                padding:12px;
                box-sizing:border-box;
              "
            >

            <br><br>

            <button
              type="submit"

              style="
                padding:12px 20px;
                cursor:pointer;
              "
            >
              Download Etsy Data
            </button>

          </form>

        </body>

      </html>
    `);
  }
);

/* =========================================================
   DOWNLOAD
========================================================= */

app.post(
  "/download",
  async (req, res) => {

    try {

      if (!CONNECTOR_SECRET) {

        return res
          .status(500)
          .send(
            "CONNECTOR_SECRET is not configured."
          );
      }

      const supplied =
        req.body.secret ||
        "";

      if (
        supplied !==
        CONNECTOR_SECRET
      ) {

        return res
          .status(401)
          .send(
            "Invalid CONNECTOR_SECRET."
          );
      }

      const data =
        await createExport();

      const json =
        JSON.stringify(
          data,
          null,
          2
        );

      res.setHeader(
        "Content-Type",
        "application/json"
      );

      res.setHeader(
        "Content-Disposition",
        'attachment; filename="digiphilestudio-etsy-export.json"'
      );

      res.send(json);

    } catch (error) {

      res
        .status(500)
        .send(
          `Export failed: ${error.message}`
        );
    }
  }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `DigiPhileStudio Etsy API running on port ${PORT}`
    );

  }
);
