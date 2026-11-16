import { NextResponse } from "next/server";
import { verifyAdminRequest, isInvalidOrPlaceholderSecret, recordSecurityAudit } from "@/lib/securityControls";

/**
 * Task 04: GET side-effects removed from setup-master.
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
      error: "GET setup-master is disabled. Use authenticated POST.",
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
    const auditId = recordSecurityAudit("ADMIN_SETUP_MASTER", "MISSING_OPENAI_CONFIG", "DENY", {
      hasApiKey: !isInvalidOrPlaceholderSecret(apiKey),
      hasVectorStoreId: !isInvalidOrPlaceholderSecret(vectorStoreId),
    });
    return NextResponse.json(
      {
        success: false,
        error: "Required OpenAI credentials or Vector Store ID are missing.",
        auditId,
      },
      { status: 503 }
    );
  }

  const auditId = recordSecurityAudit("ADMIN_SETUP_MASTER", "MASTER_CONFIG_VERIFIED", "ALLOW", {
    externalWritePerformed: false,
  });

  return NextResponse.json(
    {
      success: true,
      mode: "Master 4.0 Verified (Responses API + Vector Store)",
      externalWritePerformed: false,
      auditId,
    },
    { status: 200 }
  );
}
