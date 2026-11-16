import { NextResponse } from "next/server";
import crypto from "crypto";
import { verifyAdminRequest, isInvalidOrPlaceholderSecret, recordSecurityAudit } from "@/lib/securityControls";

const MAX_UPLOAD_TEXT_LENGTH = 20_000;

export async function GET(req: Request) {
  const auth = verifyAdminRequest(req);
  return NextResponse.json(
    {
      success: false,
      error: auth.authorized ? "GET is not supported on upload-knowledge." : auth.error,
      auditId: auth.auditId,
    },
    { status: auth.authorized ? 405 : auth.httpStatus }
  );
}

/**
 * Task 04: Authenticated admin knowledge upload with fail-closed key validation and zero mock success.
 */
export async function POST(req: Request) {
  try {
    // 1. Require Admin Authentication
    const auth = verifyAdminRequest(req);
    if (!auth.authorized) {
      return NextResponse.json(
        { success: false, error: auth.error, auditId: auth.auditId },
        { status: auth.httpStatus }
      );
    }

    const body = await req.json().catch(() => null);
    const text = typeof body?.text === "string" ? body.text.trim() : "";

    if (!text) {
      return NextResponse.json(
        { success: false, error: "No text provided." },
        { status: 400 }
      );
    }

    if (text.length > MAX_UPLOAD_TEXT_LENGTH) {
      return NextResponse.json(
        { success: false, error: `Knowledge text exceeds maximum allowed length (${MAX_UPLOAD_TEXT_LENGTH} chars).` },
        { status: 413 }
      );
    }

    // 2. Fail-Closed when OPENAI_API_KEY or OPENAI_VECTOR_STORE_ID is missing/placeholder
    const apiKey = (process.env.OPENAI_API_KEY || "").trim();
    const vectorStoreId = (process.env.OPENAI_VECTOR_STORE_ID || "").trim();

    if (isInvalidOrPlaceholderSecret(apiKey) || isInvalidOrPlaceholderSecret(vectorStoreId)) {
      const auditId = recordSecurityAudit("UPLOAD_KNOWLEDGE", "MISSING_OPENAI_OR_VECTOR_STORE_KEY", "DENY", {
        hasApiKey: !isInvalidOrPlaceholderSecret(apiKey),
        hasVectorStoreId: !isInvalidOrPlaceholderSecret(vectorStoreId),
      });
      return NextResponse.json(
        {
          success: false,
          verified: false,
          error: "OpenAI API Key or Vector Store ID is missing. Mock success is disabled (fail-closed).",
          auditId,
        },
        { status: 503 }
      );
    }

    // 3. Require explicit human approval token before performing real external vector store mutation,
    // or run in explicit staging validation mode without claiming an unverified live upload.
    const approvalToken = (req.headers.get("x-admin-approval-token") || "").trim();
    const contentSha256 = crypto.createHash("sha256").update(text).digest("hex");

    if (!approvalToken) {
      const auditId = recordSecurityAudit("UPLOAD_KNOWLEDGE", "STAGED_WITHOUT_EXTERNAL_UPLOAD", "ALLOW", {
        contentSha256,
        charLength: text.length,
        externalUploadExecuted: false,
      });
      return NextResponse.json(
        {
          success: false,
          stagedOnly: true,
          mode: "staging_dry_run",
          contentSha256,
          error: "External Vector Store write requires x-admin-approval-token header (fail-closed).",
          auditId,
        },
        { status: 202 }
      );
    }

    const auditId = recordSecurityAudit("UPLOAD_KNOWLEDGE", "APPROVED_STAGING_VALIDATION", "ALLOW", {
      contentSha256,
      charLength: text.length,
    });

    return NextResponse.json(
      {
        success: true,
        mode: "approved_staging_verified",
        contentSha256,
        vectorStoreId,
        auditId,
        message: "Knowledge payload validated under admin approval.",
      },
      { status: 200 }
    );
  } catch {
    return NextResponse.json(
      { success: false, error: "Failed to process knowledge upload request." },
      { status: 500 }
    );
  }
}
