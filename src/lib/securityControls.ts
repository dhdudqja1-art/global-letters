import crypto from "crypto";
import { db, isMockDb } from "@/lib/firebaseAdmin";

export type PaidProductType = "beta" | "deep" | "recovery" | "gift";
export type AllProductType = "random" | "free" | "extra" | PaidProductType;

export interface ProductSpec {
  id: AllProductType;
  paid: boolean;
  usd: string;
  krw: number;
  maxInputChars: number;
  dailyFreeLimit: number;
}

export const OFFICIAL_PRODUCT_CATALOG: Record<AllProductType, ProductSpec> = {
  random: { id: "random", paid: false, usd: "0.00", krw: 0, maxInputChars: 500, dailyFreeLimit: 3 },
  free: { id: "free", paid: false, usd: "0.00", krw: 0, maxInputChars: 3000, dailyFreeLimit: 3 },
  extra: { id: "extra", paid: false, usd: "0.00", krw: 0, maxInputChars: 3000, dailyFreeLimit: 2 },
  beta: { id: "beta", paid: true, usd: "3.99", krw: 5000, maxInputChars: 6000, dailyFreeLimit: 0 },
  deep: { id: "deep", paid: true, usd: "6.99", krw: 9000, maxInputChars: 8000, dailyFreeLimit: 0 },
  recovery: { id: "recovery", paid: true, usd: "21.99", krw: 29000, maxInputChars: 10000, dailyFreeLimit: 0 },
  gift: { id: "gift", paid: true, usd: "9.99", krw: 12000, maxInputChars: 6000, dailyFreeLimit: 0 },
};

export interface VerifiedPaymentRecord {
  orderID: string;
  captureId: string;
  productType: PaidProductType;
  amountUsd: string;
  currency: string;
  payeeMerchantId: string | null;
  payeeEmail: string | null;
  auditId: string;
  idempotencyKey: string;
  paymentGrantToken: string;
  verifiedAt: string;
  deliveredCount: number;
  deliveredAt?: string | null;
}

export interface WebhookEventRecord {
  idempotencyKey: string;
  eventId: string;
  transactionId: string;
  orderId: string | null;
  eventType: string;
  amountValue: string;
  currencyCode: string;
  productType: PaidProductType | null;
  payloadSha256: string;
  processedAt: string;
  status: "SUCCESS";
}

// Atomic in-process stores (paired with Firestore persistence when available)
const verifiedOrdersStore = new Map<string, VerifiedPaymentRecord>();
const captureIdToOrderMap = new Map<string, string>();
const webhookIdempotencyStore = new Map<string, WebhookEventRecord>();
const securityAuditLogs: Array<{
  auditId: string;
  timestamp: string;
  category: string;
  event: string;
  status: "ALLOW" | "DENY" | "ERROR";
  details: Record<string, unknown>;
}> = [];

// Rate-limit & cost-cap state (shared atomic counters with TTL)
interface RateLimitBucket {
  count: number;
  resetAtMs: number;
}
const rateLimitStore = new Map<string, RateLimitBucket>();
let minuteCostUsd = 0;
let minuteCostResetAt = Date.now() + 60_000;
let dailyCostUsd = 0;
let dailyCostResetAt = Date.now() + 86_400_000;

export function resetSecurityStoresForTest() {
  verifiedOrdersStore.clear();
  captureIdToOrderMap.clear();
  webhookIdempotencyStore.clear();
  securityAuditLogs.length = 0;
  rateLimitStore.clear();
  minuteCostUsd = 0;
  minuteCostResetAt = Date.now() + 60_000;
  dailyCostUsd = 0;
  dailyCostResetAt = Date.now() + 86_400_000;
}

export function getSecurityAuditLogs() {
  return [...securityAuditLogs];
}

export function recordSecurityAudit(
  category: string,
  event: string,
  status: "ALLOW" | "DENY" | "ERROR",
  details: Record<string, unknown>
): string {
  const auditId = `aud_${Date.now()}_${crypto.randomBytes(4).toString("hex")}`;
  securityAuditLogs.push({
    auditId,
    timestamp: new Date().toISOString(),
    category,
    event,
    status,
    details,
  });
  return auditId;
}

export function isInvalidOrPlaceholderSecret(val?: string | null): boolean {
  if (!val) return true;
  const trimmed = val.trim();
  if (!trimmed) return true;
  const badPatterns = [
    "여기에_",
    "붙여넣으세요",
    "dummy-key",
    "your_api_key",
    "placeholder",
    "changeme",
    "dev-secret-key-1234",
  ];
  return badPatterns.some((p) => trimmed.toLowerCase().includes(p.toLowerCase()));
}

export function getPayPalConfig() {
  const clientId = (process.env.PAYPAL_CLIENT_ID || process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID || "").trim();
  const clientSecret = (process.env.PAYPAL_CLIENT_SECRET || "").trim();
  const webhookId = (process.env.PAYPAL_WEBHOOK_ID || "").trim();
  const expectedMerchantId = (process.env.PAYPAL_EXPECTED_MERCHANT_ID || "").trim();
  const expectedPayeeEmail = (process.env.PAYPAL_EXPECTED_PAYEE_EMAIL || "").trim();
  const mode = (process.env.PAYPAL_MODE || "sandbox").trim().toLowerCase();
  const baseUrl = mode === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";

  const hasValidCredentials =
    !isInvalidOrPlaceholderSecret(clientId) && !isInvalidOrPlaceholderSecret(clientSecret);

  return {
    clientId,
    clientSecret,
    webhookId,
    expectedMerchantId,
    expectedPayeeEmail,
    mode,
    baseUrl,
    hasValidCredentials,
  };
}

function getGrantSigningSecret(): string {
  return (
    process.env.PAYMENT_GRANT_SECRET ||
    process.env.PAYPAL_CLIENT_SECRET ||
    process.env.ADMIN_SECRET_KEY ||
    "local-ephemeral-grant-signing-key-20261116"
  ).trim();
}

export function createPaymentGrantToken(
  orderID: string,
  captureId: string,
  productType: PaidProductType
): string {
  const payload = `${orderID}:${captureId}:${productType}`;
  const sig = crypto.createHmac("sha256", getGrantSigningSecret()).update(payload).digest("hex");
  return `${Buffer.from(payload, "utf8").toString("base64url")}.${sig}`;
}

export function verifyPaymentGrantTokenSignature(
  token: string,
  expectedOrderID: string,
  expectedProductType: PaidProductType
): boolean {
  if (!token || !token.includes(".")) return false;
  const [encodedPayload, sig] = token.split(".");
  if (!encodedPayload || !sig) return false;
  try {
    const decoded = Buffer.from(encodedPayload, "base64url").toString("utf8");
    const [orderID, captureId, productType] = decoded.split(":");
    if (orderID !== expectedOrderID || productType !== expectedProductType || !captureId) {
      return false;
    }
    const expectedSig = crypto
      .createHmac("sha256", getGrantSigningSecret())
      .update(decoded)
      .digest("hex");
    return crypto.timingSafeEqual(Buffer.from(sig, "hex"), Buffer.from(expectedSig, "hex"));
  } catch {
    return false;
  }
}

export function resolveProductTypeByUsd(amountValue: string, currencyCode: string): PaidProductType | null {
  if (currencyCode !== "USD") return null;
  const normalized = Number(amountValue).toFixed(2);
  for (const spec of Object.values(OFFICIAL_PRODUCT_CATALOG)) {
    if (spec.paid && spec.usd === normalized) {
      return spec.id as PaidProductType;
    }
  }
  return null;
}

export interface VerifyOrderInput {
  orderID?: string;
  productType?: string;
  idempotencyKey?: string;
  fetchImpl?: typeof fetch;
}

export interface VerifyOrderResult {
  httpStatus: number;
  body: {
    success: boolean;
    verified: boolean;
    error?: string;
    duplicate?: boolean;
    auditId: string;
    idempotencyKey?: string;
    orderID?: string;
    captureId?: string;
    productType?: PaidProductType;
    paymentGrantToken?: string;
  };
}

/**
 * Task 01: Fail-closed PayPal Order & Capture Verification
 */
export async function verifyPayPalOrderServerSide(input: VerifyOrderInput): Promise<VerifyOrderResult> {
  const fetchFn = input.fetchImpl || globalThis.fetch;
  const orderID = (input.orderID || "").trim();
  const requestedProduct = (input.productType || "beta").trim() as AllProductType;

  // 1. Validate Order ID format
  if (!orderID || !/^[A-Za-z0-9_-]{6,64}$/.test(orderID)) {
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "INVALID_ORDER_ID", "DENY", {
      orderIdProvided: Boolean(orderID),
    });
    return {
      httpStatus: 400,
      body: {
        success: false,
        verified: false,
        error: "Valid Order ID is required.",
        auditId,
      },
    };
  }

  // 2. Validate Product Type against official server catalog
  const productSpec = OFFICIAL_PRODUCT_CATALOG[requestedProduct];
  if (!productSpec || !productSpec.paid) {
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "INVALID_PRODUCT_TYPE", "DENY", {
      orderID,
      requestedProduct,
    });
    return {
      httpStatus: 400,
      body: {
        success: false,
        verified: false,
        error: "Invalid or non-paid product type specified.",
        auditId,
      },
    };
  }

  // 3. Fail-Closed check on PayPal credentials (NEVER return mock verified:true!)
  const cfg = getPayPalConfig();
  if (!cfg.hasValidCredentials) {
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "MISSING_PAYPAL_CREDENTIALS", "DENY", {
      orderID,
      mode: cfg.mode,
      hasClientId: !isInvalidOrPlaceholderSecret(cfg.clientId),
      hasClientSecret: !isInvalidOrPlaceholderSecret(cfg.clientSecret),
    });
    return {
      httpStatus: 503,
      body: {
        success: false,
        verified: false,
        error: "PayPal payment verification is unavailable due to missing server credentials (fail-closed).",
        auditId,
      },
    };
  }

  // 4. Check Idempotency / Duplicate Order Before or After Verification
  const existingRecord = verifiedOrdersStore.get(orderID);
  if (existingRecord) {
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "DUPLICATE_ORDER_CALLBACK", "DENY", {
      orderID,
      captureId: existingRecord.captureId,
      previousAuditId: existingRecord.auditId,
    });
    return {
      httpStatus: 409,
      body: {
        success: false,
        verified: false,
        duplicate: true,
        error: "Duplicate order verification request: order has already been verified/processed.",
        auditId,
        idempotencyKey: existingRecord.idempotencyKey,
      },
    };
  }

  try {
    // 5. Obtain OAuth2 Access Token from PayPal
    const auth = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
    const tokenResponse = await fetchFn(`${cfg.baseUrl}/v1/oauth2/token`, {
      method: "POST",
      body: "grant_type=client_credentials",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    if (!tokenResponse.ok) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "OAUTH_TOKEN_FAILURE", "ERROR", {
        orderID,
        httpStatus: tokenResponse.status,
      });
      return {
        httpStatus: 502,
        body: {
          success: false,
          verified: false,
          error: "Failed to authenticate with PayPal.",
          auditId,
        },
      };
    }

    const tokenData = await tokenResponse.json();
    if (!tokenData?.access_token) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "EMPTY_OAUTH_TOKEN", "ERROR", { orderID });
      return {
        httpStatus: 502,
        body: {
          success: false,
          verified: false,
          error: "Invalid authentication response from PayPal.",
          auditId,
        },
      };
    }

    // 6. Fetch Order Details from PayPal (/v2/checkout/orders/{orderID})
    const orderResponse = await fetchFn(`${cfg.baseUrl}/v2/checkout/orders/${encodeURIComponent(orderID)}`, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        "Content-Type": "application/json",
      },
    });

    if (!orderResponse.ok) {
      const status = orderResponse.status === 404 ? 404 : 502;
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "ORDER_LOOKUP_FAILED", "DENY", {
        orderID,
        paypalHttpStatus: orderResponse.status,
      });
      return {
        httpStatus: status,
        body: {
          success: false,
          verified: false,
          error: status === 404 ? "Order ID not found on PayPal." : "Failed to fetch order details from PayPal.",
          auditId,
        },
      };
    }

    const orderData = await orderResponse.json();

    // 7. Verify Order Status & Intent
    if (orderData.status !== "COMPLETED" || (orderData.intent && orderData.intent !== "CAPTURE")) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "ORDER_NOT_COMPLETED", "DENY", {
        orderID,
        orderStatus: orderData.status || "UNKNOWN",
        intent: orderData.intent || "UNKNOWN",
      });
      return {
        httpStatus: 400,
        body: {
          success: false,
          verified: false,
          error: `Order is not completed (status: ${orderData.status || "UNKNOWN"}).`,
          auditId,
        },
      };
    }

    // 8. Verify Capture Status
    const purchaseUnit = orderData.purchase_units?.[0];
    const capture = purchaseUnit?.payments?.captures?.[0];
    if (!capture || capture.status !== "COMPLETED" || !capture.id) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "CAPTURE_NOT_COMPLETED", "DENY", {
        orderID,
        captureStatus: capture?.status || "MISSING",
      });
      return {
        httpStatus: 400,
        body: {
          success: false,
          verified: false,
          error: "Order payment capture is missing or not completed.",
          auditId,
        },
      };
    }

    // Check if capture.id was already used under a different orderID
    if (captureIdToOrderMap.has(capture.id)) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "DUPLICATE_CAPTURE_ID", "DENY", {
        orderID,
        captureId: capture.id,
      });
      return {
        httpStatus: 409,
        body: {
          success: false,
          verified: false,
          duplicate: true,
          error: "Payment capture ID has already been processed.",
          auditId,
        },
      };
    }

    // 9. Verify Amount & Currency against Official Server Catalog
    const captureAmount = capture.amount || purchaseUnit?.amount;
    const actualCurrency = captureAmount?.currency_code || "";
    const actualValue = captureAmount?.value ? Number(captureAmount.value).toFixed(2) : "";
    if (actualCurrency !== "USD" || actualValue !== productSpec.usd) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "AMOUNT_OR_CURRENCY_MISMATCH", "DENY", {
        orderID,
        expectedCurrency: "USD",
        actualCurrency,
        expectedValue: productSpec.usd,
        actualValue,
        requestedProduct,
      });
      return {
        httpStatus: 400,
        body: {
          success: false,
          verified: false,
          error: `Payment amount/currency mismatch (expected USD ${productSpec.usd}, got ${actualCurrency} ${actualValue}).`,
          auditId,
        },
      };
    }

    // 10. Verify Payee Account (Merchant ID / Payee Email) if configured
    const payeeMerchantId = purchaseUnit?.payee?.merchant_id || null;
    const payeeEmail = purchaseUnit?.payee?.email_address || null;
    if (cfg.expectedMerchantId && payeeMerchantId !== cfg.expectedMerchantId) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "PAYEE_MERCHANT_MISMATCH", "DENY", {
        orderID,
        payeeMerchantId,
      });
      return {
        httpStatus: 400,
        body: {
          success: false,
          verified: false,
          error: "Payment payee merchant account mismatch.",
          auditId,
        },
      };
    }
    if (cfg.expectedPayeeEmail && payeeEmail !== cfg.expectedPayeeEmail) {
      const auditId = recordSecurityAudit("PAYPAL_VERIFY", "PAYEE_EMAIL_MISMATCH", "DENY", {
        orderID,
      });
      return {
        httpStatus: 400,
        body: {
          success: false,
          verified: false,
          error: "Payment payee email account mismatch.",
          auditId,
        },
      };
    }

    // 11. Record Verified Order & Issue One-Time Delivery Token
    const idempotencyKey = input.idempotencyKey || `order:${orderID}:capture:${capture.id}`;
    const paymentGrantToken = createPaymentGrantToken(
      orderID,
      capture.id,
      productSpec.id as PaidProductType
    );
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "ORDER_VERIFIED_SUCCESS", "ALLOW", {
      orderID,
      captureId: capture.id,
      productType: productSpec.id,
      amountUsd: actualValue,
      currency: actualCurrency,
      idempotencyKey,
    });

    const record: VerifiedPaymentRecord = {
      orderID,
      captureId: capture.id,
      productType: productSpec.id as PaidProductType,
      amountUsd: actualValue,
      currency: actualCurrency,
      payeeMerchantId,
      payeeEmail,
      auditId,
      idempotencyKey,
      paymentGrantToken,
      verifiedAt: new Date().toISOString(),
      deliveredCount: 0,
    };

    verifiedOrdersStore.set(orderID, record);
    captureIdToOrderMap.set(capture.id, orderID);

    // Persist sanitized verification metadata to Firestore when available
    try {
      if (db && !isMockDb) {
        await db.collection("verified_orders").doc(orderID).set({
          orderID,
          captureId: capture.id,
          productType: productSpec.id,
          amountUsd: actualValue,
          currency: actualCurrency,
          auditId,
          idempotencyKey,
          verifiedAt: record.verifiedAt,
          deliveredCount: 0,
        });
      }
    } catch {
      // In-memory store still enforces single-delivery within the instance
    }

    return {
      httpStatus: 200,
      body: {
        success: true,
        verified: true,
        auditId,
        idempotencyKey,
        orderID,
        captureId: capture.id,
        productType: productSpec.id as PaidProductType,
        paymentGrantToken,
      },
    };
  } catch (err: any) {
    const auditId = recordSecurityAudit("PAYPAL_VERIFY", "INTERNAL_EXCEPTION", "ERROR", {
      orderID,
      message: err?.message || "Unknown error",
    });
    return {
      httpStatus: 500,
      body: {
        success: false,
        verified: false,
        error: "Failed to verify payment due to an internal error.",
        auditId,
      },
    };
  }
}

/**
 * Atomically consumes a verified payment grant so that a single paid order can only deliver 1 letter.
 */
export function consumeVerifiedPaymentGrant(
  orderID?: string,
  productType?: string,
  paymentGrantToken?: string
): { allowed: boolean; httpStatus: number; error?: string; auditId: string } {
  if (!orderID || !paymentGrantToken || !productType) {
    const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "MISSING_PAYMENT_PROOF", "DENY", {
      hasOrderID: Boolean(orderID),
      hasGrantToken: Boolean(paymentGrantToken),
      productType: productType || "unknown",
    });
    return {
      allowed: false,
      httpStatus: 401,
      error: "Paid prescription requires a verified PayPal orderID and paymentGrantToken.",
      auditId,
    };
  }

  const record = verifiedOrdersStore.get(orderID);
  if (!record) {
    const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "UNVERIFIED_ORDER_ID", "DENY", {
      orderID,
      productType,
    });
    return {
      allowed: false,
      httpStatus: 403,
      error: "Order ID has not been verified by the server.",
      auditId,
    };
  }

  if (record.productType !== productType) {
    const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "PRODUCT_TIER_MISMATCH", "DENY", {
      orderID,
      verifiedTier: record.productType,
      requestedTier: productType,
    });
    return {
      allowed: false,
      httpStatus: 403,
      error: "Requested product tier does not match the verified payment tier.",
      auditId,
    };
  }

  if (
    record.paymentGrantToken !== paymentGrantToken ||
    !verifyPaymentGrantTokenSignature(paymentGrantToken, orderID, record.productType)
  ) {
    const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "INVALID_GRANT_SIGNATURE", "DENY", {
      orderID,
      productType,
    });
    return {
      allowed: false,
      httpStatus: 403,
      error: "Invalid payment grant token signature.",
      auditId,
    };
  }

  if (record.deliveredCount >= 1) {
    const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "DUPLICATE_DELIVERY_BLOCKED", "DENY", {
      orderID,
      captureId: record.captureId,
      deliveredCount: record.deliveredCount,
    });
    return {
      allowed: false,
      httpStatus: 409,
      error: "This payment order has already been used to generate a prescription.",
      auditId,
    };
  }

  record.deliveredCount += 1;
  record.deliveredAt = new Date().toISOString();
  const auditId = recordSecurityAudit("PAYMENT_ENTITLEMENT", "GRANT_CONSUMED_ONCE", "ALLOW", {
    orderID,
    captureId: record.captureId,
    productType: record.productType,
    deliveredCount: record.deliveredCount,
  });

  return { allowed: true, httpStatus: 200, auditId };
}

/**
 * Task 02: Official PayPal Webhook Signature Verification & Idempotent Processing
 */
export interface VerifyWebhookInput {
  rawBody: string;
  headers: {
    transmissionId?: string | null;
    transmissionTime?: string | null;
    certUrl?: string | null;
    authAlgo?: string | null;
    transmissionSig?: string | null;
  };
  fetchImpl?: typeof fetch;
}

export interface VerifyWebhookResult {
  httpStatus: number;
  body: {
    status: "success" | "duplicate_ignored" | "ignored" | "failed" | "error";
    verified: boolean;
    message: string;
    auditId: string;
    idempotencyKey?: string;
  };
}

export async function verifyAndProcessPayPalWebhook(
  input: VerifyWebhookInput
): Promise<VerifyWebhookResult> {
  const fetchFn = input.fetchImpl || globalThis.fetch;
  const { transmissionId, transmissionTime, certUrl, authAlgo, transmissionSig } = input.headers;

  // 1. Require all 5 official PayPal signature headers
  if (!transmissionId || !transmissionTime || !certUrl || !authAlgo || !transmissionSig) {
    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "MISSING_SIGNATURE_HEADERS", "DENY", {
      hasTransmissionId: Boolean(transmissionId),
      hasTransmissionTime: Boolean(transmissionTime),
      hasCertUrl: Boolean(certUrl),
      hasAuthAlgo: Boolean(authAlgo),
      hasTransmissionSig: Boolean(transmissionSig),
    });
    return {
      httpStatus: 401,
      body: {
        status: "failed",
        verified: false,
        message: "Missing required PayPal webhook signature headers.",
        auditId,
      },
    };
  }

  // 2. Require valid PayPal credentials and PAYPAL_WEBHOOK_ID
  const cfg = getPayPalConfig();
  if (!cfg.hasValidCredentials || isInvalidOrPlaceholderSecret(cfg.webhookId)) {
    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "MISSING_WEBHOOK_CONFIG", "DENY", {
      hasCredentials: cfg.hasValidCredentials,
      hasWebhookId: !isInvalidOrPlaceholderSecret(cfg.webhookId),
    });
    return {
      httpStatus: 503,
      body: {
        status: "failed",
        verified: false,
        message: "PayPal webhook verification is not configured on the server (fail-closed).",
        auditId,
      },
    };
  }

  // 3. Parse JSON body safely (never logging rawBody or PII)
  let eventData: any;
  try {
    eventData = JSON.parse(input.rawBody);
  } catch {
    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "MALFORMED_JSON_PAYLOAD", "DENY", {});
    return {
      httpStatus: 400,
      body: {
        status: "failed",
        verified: false,
        message: "Malformed JSON webhook body.",
        auditId,
      },
    };
  }

  const eventId = (eventData?.id || "").trim();
  const eventType = (eventData?.event_type || "").trim();
  const resource = eventData?.resource || {};
  const transactionId = (resource?.id || "").trim();

  if (!eventId || !eventType) {
    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "MISSING_EVENT_ID_OR_TYPE", "DENY", {});
    return {
      httpStatus: 400,
      body: {
        status: "failed",
        verified: false,
        message: "Missing webhook event ID or event_type.",
        auditId,
      },
    };
  }

  try {
    // 4. Get PayPal OAuth token
    const auth = Buffer.from(`${cfg.clientId}:${cfg.clientSecret}`).toString("base64");
    const tokenRes = await fetchFn(`${cfg.baseUrl}/v1/oauth2/token`, {
      method: "POST",
      body: "grant_type=client_credentials",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });

    if (!tokenRes.ok) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "OAUTH_FAILURE", "ERROR", {
        httpStatus: tokenRes.status,
      });
      return {
        httpStatus: 502,
        body: {
          status: "error",
          verified: false,
          message: "Failed to authenticate with PayPal for webhook verification.",
          auditId,
        },
      };
    }

    const tokenJson = await tokenRes.json();

    // 5. Call Official PayPal /v1/notifications/verify-webhook-signature API
    const verifyRes = await fetchFn(`${cfg.baseUrl}/v1/notifications/verify-webhook-signature`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${tokenJson.access_token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        auth_algo: authAlgo,
        cert_url: certUrl,
        transmission_id: transmissionId,
        transmission_sig: transmissionSig,
        transmission_time: transmissionTime,
        webhook_id: cfg.webhookId,
        webhook_event: eventData,
      }),
    });

    if (!verifyRes.ok) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "SIGNATURE_API_HTTP_ERROR", "DENY", {
        eventId,
        httpStatus: verifyRes.status,
      });
      return {
        httpStatus: 401,
        body: {
          status: "failed",
          verified: false,
          message: "PayPal webhook signature verification request failed.",
          auditId,
        },
      };
    }

    const verifyJson = await verifyRes.json();
    if (verifyJson?.verification_status !== "SUCCESS") {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "SIGNATURE_VERIFICATION_REJECTED", "DENY", {
        eventId,
        verificationStatus: verifyJson?.verification_status || "FAILURE",
      });
      return {
        httpStatus: 401,
        body: {
          status: "failed",
          verified: false,
          message: "PayPal webhook signature is invalid.",
          auditId,
        },
      };
    }

    // 6. Handle non-capture events safely without mutating payment state
    if (eventType !== "PAYMENT.CAPTURE.COMPLETED") {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "NON_CAPTURE_EVENT_IGNORED", "ALLOW", {
        eventId,
        eventType,
      });
      return {
        httpStatus: 200,
        body: {
          status: "ignored",
          verified: true,
          message: `Event type ${eventType} acknowledged without state change.`,
          auditId,
        },
      };
    }

    // 7. Validate capture ID, status, amount, currency, payee, and order linkage
    if (!transactionId || resource?.status !== "COMPLETED") {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "INVALID_CAPTURE_RESOURCE", "DENY", {
        eventId,
        transactionId,
        resourceStatus: resource?.status || "MISSING",
      });
      return {
        httpStatus: 400,
        body: {
          status: "failed",
          verified: false,
          message: "Capture resource is missing ID or not in COMPLETED state.",
          auditId,
        },
      };
    }

    const amountValue = resource?.amount?.value ? Number(resource.amount.value).toFixed(2) : "";
    const currencyCode = resource?.amount?.currency_code || "";
    const matchedProductType = resolveProductTypeByUsd(amountValue, currencyCode);

    if (!matchedProductType) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "WEBHOOK_AMOUNT_CURRENCY_MISMATCH", "DENY", {
        eventId,
        transactionId,
        amountValue,
        currencyCode,
      });
      return {
        httpStatus: 400,
        body: {
          status: "failed",
          verified: false,
          message: "Webhook payment amount or currency does not match any official product.",
          auditId,
        },
      };
    }

    const payeeMerchantId = resource?.payee?.merchant_id || eventData?.resource?.seller_receivable_breakdown?.payee?.merchant_id || null;
    const payeeEmail = resource?.payee?.email_address || null;
    if (cfg.expectedMerchantId && payeeMerchantId !== cfg.expectedMerchantId) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "WEBHOOK_PAYEE_MISMATCH", "DENY", {
        eventId,
        transactionId,
      });
      return {
        httpStatus: 400,
        body: {
          status: "failed",
          verified: false,
          message: "Webhook payee merchant ID mismatch.",
          auditId,
        },
      };
    }
    if (cfg.expectedPayeeEmail && payeeEmail !== cfg.expectedPayeeEmail) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "WEBHOOK_PAYEE_EMAIL_MISMATCH", "DENY", {
        eventId,
        transactionId,
      });
      return {
        httpStatus: 400,
        body: {
          status: "failed",
          verified: false,
          message: "Webhook payee email mismatch.",
          auditId,
        },
      };
    }

    // 8. Atomic Idempotency Check (eventId + transactionId)
    const idempotencyKey = `webhook:${eventId}:${transactionId}`;
    if (webhookIdempotencyStore.has(idempotencyKey)) {
      const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "DUPLICATE_WEBHOOK_IGNORED", "ALLOW", {
        eventId,
        transactionId,
        idempotencyKey,
      });
      return {
        httpStatus: 200,
        body: {
          status: "duplicate_ignored",
          verified: true,
          message: "Duplicate webhook event ignored idempotently.",
          auditId,
          idempotencyKey,
        },
      };
    }

    const payloadSha256 = crypto.createHash("sha256").update(input.rawBody).digest("hex");
    const orderId = resource?.supplementary_data?.related_ids?.order_id || null;

    const record: WebhookEventRecord = {
      idempotencyKey,
      eventId,
      transactionId,
      orderId,
      eventType,
      amountValue,
      currencyCode,
      productType: matchedProductType,
      payloadSha256,
      processedAt: new Date().toISOString(),
      status: "SUCCESS",
    };

    webhookIdempotencyStore.set(idempotencyKey, record);

    // Save sanitized record (NO raw_payload, NO customer PII) to Firestore payments collection
    if (db) {
      await db.collection("payments").doc(idempotencyKey).set({
        idempotency_key: idempotencyKey,
        event_id: eventId,
        transaction_id: transactionId,
        order_id: orderId,
        amount: { value: amountValue, currency_code: currencyCode },
        product_type: matchedProductType,
        payload_sha256: payloadSha256,
        status: "SUCCESS",
        timestamp: record.processedAt,
      });
    }

    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "WEBHOOK_PROCESSED_ONCE", "ALLOW", {
      eventId,
      transactionId,
      idempotencyKey,
      productType: matchedProductType,
      amountValue,
      currencyCode,
    });

    return {
      httpStatus: 200,
      body: {
        status: "success",
        verified: true,
        message: "Webhook verified and recorded once.",
        auditId,
        idempotencyKey,
      },
    };
  } catch (err: any) {
    const auditId = recordSecurityAudit("PAYPAL_WEBHOOK", "WEBHOOK_PROCESSING_ERROR", "ERROR", {
      eventId,
      message: err?.message || "Unknown error",
    });
    return {
      httpStatus: 500,
      body: {
        status: "error",
        verified: false,
        message: "Internal webhook processing error.",
        auditId,
      },
    };
  }
}

export function getWebhookProcessedCount(): number {
  return webhookIdempotencyStore.size;
}

/**
 * Task 04: Admin Authentication & CSRF / Role Verification
 */
export function verifyAdminRequest(req: Request): {
  authorized: boolean;
  httpStatus: number;
  error?: string;
  auditId: string;
} {
  const adminSecret = (process.env.ADMIN_SECRET_KEY || "").trim();
  if (isInvalidOrPlaceholderSecret(adminSecret)) {
    const auditId = recordSecurityAudit("ADMIN_AUTH", "ADMIN_SECRET_NOT_CONFIGURED", "DENY", {
      method: req.method,
    });
    return {
      authorized: false,
      httpStatus: 403,
      error: "Admin operations are disabled because ADMIN_SECRET_KEY is not configured.",
      auditId,
    };
  }

  const authHeader = req.headers.get("authorization") || "";
  const bearerToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : "";
  const roleHeader = (req.headers.get("x-admin-role") || "").trim();

  if (!bearerToken || bearerToken !== adminSecret || roleHeader !== "admin") {
    const auditId = recordSecurityAudit("ADMIN_AUTH", "UNAUTHORIZED_ADMIN_ATTEMPT", "DENY", {
      method: req.method,
      hasBearer: Boolean(bearerToken),
      roleHeader,
    });
    return {
      authorized: false,
      httpStatus: 401,
      error: "Unauthorized: valid admin Bearer token and x-admin-role header required.",
      auditId,
    };
  }

  const auditId = recordSecurityAudit("ADMIN_AUTH", "ADMIN_AUTHORIZED", "ALLOW", {
    method: req.method,
  });
  return { authorized: true, httpStatus: 200, auditId };
}

/**
 * Task 05: Shared Rate Limiting, Payload Size Limit, Cost Cap, and Indirect Prompt Injection Guard
 */
export const EST_COST_PER_CALL_USD: Record<AllProductType, number> = {
  random: 0,
  free: 0.015,
  extra: 0.015,
  beta: 0.03,
  deep: 0.045,
  recovery: 0.08,
  gift: 0.03,
};

export function checkAndReserveRateLimitAndCost(params: {
  actorKey: string;
  productType: AllProductType;
  maxRequestsPerWindow?: number;
  windowMs?: number;
  minuteBudgetUsd?: number;
  dailyBudgetUsd?: number;
}): {
  allowed: boolean;
  httpStatus: number;
  error?: string;
  remainingRequests?: number;
  currentCount?: number;
  auditId: string;
} {
  const now = Date.now();
  const maxReq =
    params.maxRequestsPerWindow ??
    Number(process.env.RATE_LIMIT_MAX_PER_WINDOW || OFFICIAL_PRODUCT_CATALOG[params.productType]?.dailyFreeLimit || 3);
  const windowMs = params.windowMs ?? Number(process.env.RATE_LIMIT_WINDOW_MS || 24 * 60 * 60 * 1000);
  const minBudget = params.minuteBudgetUsd ?? Number(process.env.AI_MINUTE_BUDGET_USD || 0.5);
  const dayBudget = params.dailyBudgetUsd ?? Number(process.env.AI_DAILY_BUDGET_USD || 5.0);

  // Reset cost windows if expired
  if (now >= minuteCostResetAt) {
    minuteCostUsd = 0;
    minuteCostResetAt = now + 60_000;
  }
  if (now >= dailyCostResetAt) {
    dailyCostUsd = 0;
    dailyCostResetAt = now + 86_400_000;
  }

  const estCost = EST_COST_PER_CALL_USD[params.productType] ?? 0.02;

  // 1. Check rate limit bucket for non-paid or burst-limited requests
  if (!OFFICIAL_PRODUCT_CATALOG[params.productType].paid && params.productType !== "random") {
    const bucketKey = `${params.productType}:${params.actorKey}`;
    let bucket = rateLimitStore.get(bucketKey);
    if (!bucket || now >= bucket.resetAtMs) {
      bucket = { count: 0, resetAtMs: now + windowMs };
      rateLimitStore.set(bucketKey, bucket);
    }

    if (bucket.count >= maxReq) {
      const auditId = recordSecurityAudit("RATE_LIMIT", "QUOTA_EXCEEDED", "DENY", {
        actorKeyHash: crypto.createHash("sha256").update(params.actorKey).digest("hex").slice(0, 12),
        productType: params.productType,
        count: bucket.count,
        maxReq,
      });
      return {
        allowed: false,
        httpStatus: 429,
        error: "일일 무료 이용 횟수를 초과했습니다. 잠시 후 또는 내일 다시 이용해 주세요.",
        remainingRequests: 0,
        currentCount: bucket.count,
        auditId,
      };
    }

    // Check cost cap before incrementing
    if (minuteCostUsd + estCost > minBudget || dailyCostUsd + estCost > dayBudget) {
      const auditId = recordSecurityAudit("COST_CAP", "BUDGET_EXCEEDED", "DENY", {
        minuteCostUsd,
        dailyCostUsd,
        estCost,
      });
      return {
        allowed: false,
        httpStatus: 429,
        error: "AI 생성 비용 안전 상한에 도달하여 요청이 일시 제한되었습니다.",
        auditId,
      };
    }

    // Atomic synchronous increment in single-threaded JS event loop
    bucket.count += 1;
    minuteCostUsd = Number((minuteCostUsd + estCost).toFixed(4));
    dailyCostUsd = Number((dailyCostUsd + estCost).toFixed(4));

    const auditId = recordSecurityAudit("RATE_LIMIT", "QUOTA_RESERVED", "ALLOW", {
      productType: params.productType,
      currentCount: bucket.count,
      remainingRequests: maxReq - bucket.count,
      minuteCostUsd,
      dailyCostUsd,
    });

    return {
      allowed: true,
      httpStatus: 200,
      remainingRequests: maxReq - bucket.count,
      currentCount: bucket.count,
      auditId,
    };
  }

  // Paid tiers still check global minute/daily runaway cost ceiling
  if (estCost > 0 && (minuteCostUsd + estCost > minBudget * 4 || dailyCostUsd + estCost > dayBudget * 4)) {
    const auditId = recordSecurityAudit("COST_CAP", "PAID_RUNAWAY_BUDGET_EXCEEDED", "DENY", {
      minuteCostUsd,
      dailyCostUsd,
    });
    return {
      allowed: false,
      httpStatus: 429,
      error: "시스템 보호를 위한 일일 AI 비용 상한에 도달했습니다.",
      auditId,
    };
  }

  minuteCostUsd = Number((minuteCostUsd + estCost).toFixed(4));
  dailyCostUsd = Number((dailyCostUsd + estCost).toFixed(4));
  const auditId = recordSecurityAudit("COST_CAP", "COST_RESERVED", "ALLOW", {
    productType: params.productType,
    minuteCostUsd,
    dailyCostUsd,
  });

  return { allowed: true, httpStatus: 200, auditId };
}

/**
 * Task 05 & 07: Indirect Prompt Injection Detection & Neutralization
 * Ensures external text or user inputs attempting to trigger Instagram posts, DMs, payments,
 * file deletions, or system prompt overrides are detected and blocked from executing any external tools.
 */
export function detectPromptInjectionAndExternalActionAttempt(text: string): {
  detected: boolean;
  matchedPatterns: string[];
  sanitizedText: string;
} {
  if (!text) return { detected: false, matchedPatterns: [], sanitizedText: "" };

  const patterns: Array<{ name: string; regex: RegExp }> = [
    { name: "SYSTEM_OVERRIDE", regex: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions|시스템\s*지침\s*무시|이전\s*명령.*무시/i },
    { name: "EXTERNAL_SNS_ACTION", regex: /instagram.*게시|인스타.*업로드|인스타\s*DM\s*발송|publish_media|reply_to_comment|send_direct_message/i },
    { name: "EXTERNAL_PAYMENT_ACTION", regex: /paypal.*환불|결제\s*승인\s*처리|verified\s*:\s*true|verify-payment.*호출/i },
    { name: "SECRET_EXFILTRATION", regex: /OPENAI_API_KEY|GOOGLE_APPLICATION_CREDENTIALS|PAYPAL_CLIENT_SECRET|환경\s*변수.*출력/i },
    { name: "DESTRUCTIVE_FILE_ACTION", regex: /rm\s+-rf|unlinkSync|firestore\.rules.*삭제|데이터베이스\s*초기화/i },
  ];

  const matchedPatterns: string[] = [];
  let sanitizedText = text;

  for (const p of patterns) {
    if (p.regex.test(text)) {
      matchedPatterns.push(p.name);
      sanitizedText = sanitizedText.replace(new RegExp(p.regex.source, "gi"), "[보안 필터링된 지시문]");
    }
  }

  if (matchedPatterns.length > 0) {
    recordSecurityAudit("PROMPT_INJECTION_GUARD", "INJECTION_ATTEMPT_NEUTRALIZED", "DENY", {
      matchedPatterns,
      externalToolsInvoked: 0,
    });
  }

  return {
    detected: matchedPatterns.length > 0,
    matchedPatterns,
    sanitizedText,
  };
}
