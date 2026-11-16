import { NextResponse } from "next/server";
import { verifyAdminRequest, recordSecurityAudit } from "@/lib/securityControls";

/**
 * Task 04: Destructive GET cleanup removed.
 * GET performs 0 file deletions and 0 external writes.
 */
export async function GET(req: Request) {
  const auth = verifyAdminRequest(req);
  if (!auth.authorized) {
    return NextResponse.json(
      {
        success: false,
        deletedFilesCount: 0,
        error: "Unauthorized or disabled: GET cleanup is forbidden.",
        auditId: auth.auditId,
      },
      { status: auth.httpStatus }
    );
  }

  const auditId = recordSecurityAudit("ADMIN_CLEANUP", "GET_SIDE_EFFECT_BLOCKED", "DENY", {
    deletedFilesCount: 0,
  });

  return NextResponse.json(
    {
      success: false,
      deletedFilesCount: 0,
      error: "Destructive GET cleanup is permanently disabled. Use POST for read-only diagnostic check.",
      auditId,
    },
    { status: 405 }
  );
}

export async function POST(req: Request) {
  const auth = verifyAdminRequest(req);
  if (!auth.authorized) {
    return NextResponse.json(
      { success: false, deletedFilesCount: 0, error: auth.error, auditId: auth.auditId },
      { status: auth.httpStatus }
    );
  }

  const auditId = recordSecurityAudit("ADMIN_CLEANUP", "SAFE_NOOP_AUDIT", "ALLOW", {
    deletedFilesCount: 0,
  });

  return NextResponse.json(
    {
      success: true,
      deletedFilesCount: 0,
      message: "Cleanup route is locked in non-destructive mode. Zero files deleted.",
      auditId,
    },
    { status: 200 }
  );
}
