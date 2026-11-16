import { NextResponse } from "next/server";
import { verifyAdminRequest, isInvalidOrPlaceholderSecret, recordSecurityAudit } from "@/lib/securityControls";

/**
 * Task 04: GET side-effects and .env.local mutation removed from setup-assistant.
 */
export async function GET(req: Request) {
  const auth = verifyAdminRequest(req);
  if (!auth.authorized) {
    return NextResponse.json(
      { success: false, error: auth.error, auditId: auth.auditId },
      { status: auth.httpStatus }
    );
  }
  return NextResponse.json(
    {
      success: false,
      error: "GET setup-assistant is disabled to prevent unintended side effects. Use authenticated POST.",
      auditId: auth.auditId,
    },
    { status: 405 }
  );
}

export async function POST(req: Request) {
  const auth = verifyAdminRequest(req);
  if (!auth.authorized) {
    return NextResponse.json(
      { success: false, error: auth.error, auditId: auth.auditId },
      { status: auth.httpStatus }
    );
  }

  const apiKey = (process.env.OPENAI_API_KEY || "").trim();
  const vectorStoreId = (process.env.OPENAI_VECTOR_STORE_ID || "").trim();

  if (isInvalidOrPlaceholderSecret(apiKey) || isInvalidOrPlaceholderSecret(vectorStoreId)) {
    const auditId = recordSecurityAudit("ADMIN_SETUP_ASSISTANT", "MISSING_OPENAI_CONFIG", "DENY", {
      hasApiKey: !isInvalidOrPlaceholderSecret(apiKey),
      hasVectorStoreId: !isInvalidOrPlaceholderSecret(vectorStoreId),
    });
    return NextResponse.json(
      {
        success: false,
        error: "OPENAI_API_KEY and OPENAI_VECTOR_STORE_ID must be configured before running admin setup.",
        auditId,
      },
      { status: 503 }
    );
  }

  const auditId = recordSecurityAudit("ADMIN_SETUP_ASSISTANT", "STAGING_CONFIG_VERIFIED", "ALLOW", {
    vectorStoreConfigured: true,
    externalWritePerformed: false,
  });

  return NextResponse.json(
    {
      success: true,
      mode: "verified_read_only_configuration",
      externalWritePerformed: false,
      auditId,
    },
    { status: 200 }
  );
}
