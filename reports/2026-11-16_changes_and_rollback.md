# 2026-11-16 변경 파일 근거 및 롤백 계획 (`changes_and_rollback.md`)

- **브랜치**: `fix/six-stage-safety-20261116`
- **기준선 커밋 SHA**: `73a85d50dc879dbb6fcdc4d113041901fcfe23a5` (원격 `main` `5a224f2` / 배포 `f93ccea` 동일 스냅샷)
- **운영 배포 상태**: **미배포 (사용자 사전 승인 게이트 준수)**

---

## 1. 우선순위별 수정 파일 및 라인 근거

### [P0] 결제 검증·웹훅·데이터베이스 최소권한
1. **[src/lib/securityControls.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/securityControls.ts)** (신규 생성, 1~658행):
   - `OFFICIAL_PRODUCT_CATALOG` (17~25행): 서버 고정 상품별 금액(`beta: $3.99`, `deep: $6.99`, `gift: $9.99`, `recovery: $21.99`) 및 최대 입력 글자수 정의.
   - `verifyPayPalOrderServerSide` (174~425행): PayPal 환경변수 누락 시 HTTP `503` + `verified: false` 반환(Fail-Closed), PayPal OAuth 및 `/v2/checkout/orders/{orderID}` 조회, `COMPLETED` 상태·캡처 ID·금액·통화·수취인 검증, 중복 주문 차단(`409`), 1회용 HMAC `paymentGrantToken` 발급.
   - `consumeVerifiedPaymentGrant` (430~498행): 유료 처방전 생성 시 검증된 주문 토큰을 원자적으로 1회만 소모(2회차 호출 시 `409 Conflict`).
   - `verifyAndProcessPayPalWebhook` (524~753행): 공식 5대 PayPal 서명 헤더 및 `PAYPAL_WEBHOOK_ID` 필수화, `/v1/notifications/verify-webhook-signature` 검증, `webhook:{event.id}:{capture.id}` 멱등 처리, `raw_payload` 원문 및 개인정보 저장 제거(`payload_sha256` 해시만 저장).
2. **[src/app/api/verify-payment/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/verify-payment/route.ts)** (1~26행):
   - 기존 Fail-Open(`return NextResponse.json({ success: true, verified: true })`) 분기를 완전 제거하고 `verifyPayPalOrderServerSide`로 일원화.
3. **[src/app/api/webhook/paypal/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/webhook/paypal/route.ts)** (1~25행):
   - 비표준 `PayPal-Signature` 헤더 단순 체크 및 `raw_payload` 저장을 제거하고 `verifyAndProcessPayPalWebhook` 호출로 교체.
4. **[firestore.rules](file:///C:/Users/user/Desktop/global-letters/firestore.rules)** (1~76행):
   - 기존 `allow read, write: if true;` 전면 허용 규칙을 제거하고 기본 거부(`allow read, write: if false;`) 및 컬렉션별 최소권한(`payments`/`verified_orders` 관리자 전용, `letters`/`consultations` 본인·관리자 전용, `reviews` 공개 조회 및 인증 생성 스키마 제한) 적용.
5. **[src/app/page.tsx](file:///C:/Users/user/Desktop/global-letters/src/app/page.tsx)** (734~760행, 1295~1320행):
   - `PayPalButtons.onApprove`에서 캡처 직후 반드시 `/api/verify-payment`를 호출하여 `verified === true` 및 `paymentGrantToken`을 받은 경우에만 `/api/generate-letter`를 호출하도록 수정하고, 개발자 결제 우회 버튼 블록을 제거.

### [P1] 관리 API 보호 및 AI 비용·속도·인젝션 통제
6. **[src/app/api/cleanup/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/cleanup/route.ts)** (1~48행):
   - `GET` 요청에서의 파일·폴더 삭제(`fs.unlinkSync`, `fs.rmdirSync`) 완전 제거(`deletedFilesCount: 0`, HTTP `401`/`405`).
7. **[src/app/api/setup-assistant/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/setup-assistant/route.ts)** (1~61행) & **[src/app/api/setup-master/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/setup-master/route.ts)** (1~58행):
   - 익명 `GET` 실행 및 `.env.local` 덮어쓰기 제거, 관리자 Bearer 인증 필수화, 환경키 누락 시 HTTP `503` Fail-Closed 처리.
8. **[src/app/api/upload-knowledge/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/upload-knowledge/route.ts)** (1~97행) & **[src/app/admin/page.tsx](file:///C:/Users/user/Desktop/global-letters/src/app/admin/page.tsx)** (377~385행):
   - 익명 호출 차단(`401`/`403`), `OPENAI_API_KEY`/`OPENAI_VECTOR_STORE_ID` 누락 시 가짜 성공(`Mock knowledge saved successfully`) 제거 및 HTTP `503` `success: false` 반환.
9. **[src/app/api/send-gift/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/send-gift/route.ts)** (272~283행):
   - 하드코딩된 기본 관리자 키(`"dev-secret-key-1234"`) 폴백 제거.
10. **[src/app/api/generate-letter/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/generate-letter/route.ts)** (1~105행):
    - `RATE_LIMIT_MAX = 99999` 제거. OpenAI 호출 전에 페이로드 크기 제한(`413`), 유료 티어 결제 토큰 검증(`401`/`403`/`409`), 원자적 쿼터·비용 상한(`429`), 간접 프롬프트 인젝션 필터링을 먼저 수행하도록 순서 교정.

### [G1 ~ G5] 6단계 증거·통제 모듈 및 검증 스크립트
11. **[src/lib/gates/index.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/gates/index.ts)** (1~608행):
    - `G1BriefingEngine`, `evaluateGoldenSet15`, `G3PerformanceLedger`, `runG4ChaosAndRecoverySuite`, `G5ActionControlGate` 구현.
12. **[scripts/g1_apps_script_briefing.gs](file:///C:/Users/user/Desktop/global-letters/scripts/g1_apps_script_briefing.gs)**, **[scripts/security_gate.py](file:///C:/Users/user/Desktop/global-letters/scripts/security_gate.py)**, **[scripts/run_six_stage_tests.ts](file:///C:/Users/user/Desktop/global-letters/scripts/run_six_stage_tests.ts)**.

---

## 2. 프로덕션 영향 분석 및 안전한 롤백 절차

### 프로덕션 배포 전 필수 확인 사항
1. **PayPal 환경변수 설정 필수**:
   - 본 패치는 `verify-payment`를 **Fail-Closed**로 전환하므로, Vercel 운영 환경에 `NEXT_PUBLIC_PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`가 등록되기 전에 프로덕션에 배포하면 유료 티어(`beta`, `deep`, `recovery`, `gift`) 결제가 HTTP `503`으로 차단됩니다. (무료 티어 `random`, `free`는 정상 작동.)
2. **Firestore 보안 규칙 배포 영향**:
   - 현재 서버측 Next.js API(`/api/track/visit`, `/api/track/review`, `/api/webhook/paypal`)는 Firebase Admin SDK를 사용하므로 `firestore.rules` 최소권한 적용 후에도 정상 작동합니다.

### 롤백(Rollback) 절차
1. **로컬 Git 롤백**:
   ```powershell
   git checkout main
   ```
2. **Vercel 배포 롤백 (향후 승인 후 배포 시 이상 발생 시)**:
   ```powershell
   npx vercel rollback dpl_DY6x9ocNWGLQsr9bGtbZV6Q8dBFR --yes
   ```
3. **Firestore 규칙 롤백 (향후 승인 후 규칙 배포 시 이상 발생 시)**:
   - 배포 전 백업한 규칙 파일로 `npx firebase deploy --only firestore:rules --project ask-one-s-heart` 즉시 복원.
