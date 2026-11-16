import { NextResponse } from "next/server";
import { verifyPayPalOrderServerSide } from "@/lib/securityControls";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => null);
    if (!body || typeof body !== "object") {
      return NextResponse.json(
        { success: false, verified: false, error: "Invalid JSON request body." },
        { status: 400 }
      );
    }

    const result = await verifyPayPalOrderServerSide({
      orderID: body.orderID,
      productType: body.productType,
      idempotencyKey: body.idempotencyKey || req.headers.get("x-idempotency-key") || undefined,
    });

    return NextResponse.json(result.body, { status: result.httpStatus });
  } catch {
    return NextResponse.json(
      { success: false, verified: false, error: "Failed to verify payment." },
      { status: 500 }
    );
  }
}
