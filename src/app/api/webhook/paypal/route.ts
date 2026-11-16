import { NextResponse } from "next/server";
import { verifyAndProcessPayPalWebhook } from "@/lib/securityControls";

export async function POST(req: Request) {
  try {
    const rawBody = await req.text();
    const result = await verifyAndProcessPayPalWebhook({
      rawBody,
      headers: {
        transmissionId: req.headers.get("paypal-transmission-id"),
        transmissionTime: req.headers.get("paypal-transmission-time"),
        certUrl: req.headers.get("paypal-cert-url"),
        authAlgo: req.headers.get("paypal-auth-algo"),
        transmissionSig: req.headers.get("paypal-transmission-sig"),
      },
    });

    return NextResponse.json(result.body, { status: result.httpStatus });
  } catch {
    return NextResponse.json(
      { status: "error", verified: false, message: "Internal webhook error." },
      { status: 500 }
    );
  }
}
