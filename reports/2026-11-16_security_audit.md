# 2026-11-16 `global-letters` (마음을 묻다) 보안 감사 및 6단계 안전성 패치 보고서

- **명령서 버전**: `2026-11-16.1`
- **작성 시각**: `2026-11-16T12:56:00+09:00`
- **대상 프로젝트**: `global-letters` (`prj_gZyk6RXhNhbsGUvhyh7SJqcGmTRO`, 팀 `team_e3K9DPzWJgGnTFpZXlzBMB6y`)
- **현재 운영 배포 ID**: `dpl_DY6x9ocNWGLQsr9bGtbZV6Q8dBFR` (`https://global-letters.vercel.app`)
- **로컬 작업 브랜치**: `fix/six-stage-safety-20261116` (기준선 커밋 `73a85d5` / 원격 `main` `5a224f2` / 배포 메타 `f93ccea`)
- **유료 외부 API 호출 및 과금**: **`0회 (0원)`** — 모든 검증은 로컬 격리 테스트 더블·에뮬레이터·FakeSink로 수행하였으며, 사용자 승인 전 프로덕션 배포·실결제·실발송을 일절 수행하지 않았습니다.

---

## 1. 기준선 진단 (작업 00)

1. **Vercel 운영 환경변수 기준선 (이름/환경만 대조, 비밀값 미조회)**:
   - 등록 확인된 키(5종, `production`/`preview`/`development` 총 15건):
     - `OPENAI_API_KEY`
     - `OPENAI_ASSISTANT_ID`
     - `OPENAI_VECTOR_STORE_ID`
     - `GCLOUD_PROJECT`
     - `GOOGLE_APPLICATION_CREDENTIALS_JSON`
   - **PayPal 관련 환경변수(`NEXT_PUBLIC_PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`, `PAYPAL_EXPECTED_MERCHANT_ID`)**: **`0개` (숨김 변수 `0개`)**.
2. **발견된 P0 / P1 취약점 및 데이터 흐름**:
   - **[P0-01] `src/app/api/verify-payment/route.ts` Fail-Open 및 프런트엔드 미검증 우회**:
     - 기존 코드 14~17행에서 `clientId` 또는 `clientSecret`이 없을 때 `return NextResponse.json({ success: true, verified: true })`를 반환하여, 운영 환경에 PayPal 키가 0개인 상태에서 호출 시 무조건 결제 검증 성공을 반환하는 **Fail-Open** 상태였음.
     - 또한 `src/app/page.tsx`의 `PayPalButtons.onApprove`가 `/api/verify-payment`를 거치지 않고 바로 `generateLetter`를 호출하며, `/api/generate-letter` 역시 유료 티어(`beta`, `deep`, `recovery`, `gift`) 요청 시 서버 측 결제 검증 토큰을 확인하지 않았음.
   - **[P0-02] `src/app/api/webhook/paypal/route.ts` 서명 진위 미검증·중복 적재·원문 저장**:
     - 비표준 `PayPal-Signature` 헤더 문자열 존재 여부만 확인하고 공식 `/v1/notifications/verify-webhook-signature` API를 호출하지 않았음.
     - 동일 `event.id` 재전송 시 멱등 키 검사가 없어 중복 적재가 발생하며, `raw_payload` 일부를 DB에 저장하고 있었음.
   - **[P0-03] `firestore.rules` 전면 개방 (`allow read, write: if true;`)**:
     - 저장소 내 `firestore.rules`가 모든 컬렉션에 대해 익명 읽기·쓰기를 허용하고 있었음. (단, 운영 Firebase 프로젝트에 실제로 게시된 규칙 해시는 읽기 전용 CLI/콘솔 토큰 범위 제한으로 미확정 상태이며, 로컬에서 최소권한 규칙으로 교체 및 에뮬레이터 검증 완료. 운영 반영은 별도 승인 후 진행.)
   - **[P1-04] 관리용 `GET` 부작용 및 가짜 성공(`Mock Success`)**:
     - `GET /api/cleanup`이 인증 없이 로컬 소스 파일(`setup-assistant/route.ts`) 삭제(`unlinkSync`, `rmdirSync`)를 시도함.
     - `GET /api/setup-assistant`, `GET /api/setup-master`가 인증 없이 OpenAI API 호출 및 `.env.local` 덮어쓰기를 수행함.
     - `POST /api/upload-knowledge`가 인증 없이 동작하며 키 누락 시에도 `success: true` 모의 응답을 반환함.
   - **[P1-05] `src/app/api/generate-letter/route.ts` 무제한 허용량(`RATE_LIMIT_MAX = 99999`) 및 선행 OpenAI 호출**:
     - `RATE_LIMIT_MAX = 99999`로 사실상 제한이 해제되어 있었고, 요청 크기 검사·유료 결제 검증·속도 제한 전에 `profileEmpathy()`가 먼저 실행되어 거부되어야 할 요청에서도 OpenAI 호출이 발생할 수 있었음.

---

## 2. P0 / P1 보안 수정 내역 (작업 01 ~ 05)

| 작업 번호 | 수정 파일 | 핵심 조치 내용 |
|---|---|---|
| **작업 01 (P0)** | [securityControls.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/securityControls.ts), [verify-payment/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/verify-payment/route.ts), [page.tsx](file:///C:/Users/user/Desktop/global-letters/src/app/page.tsx) | PayPal 환경키 미설정·플레이스홀더 시 즉시 HTTP `503` + `{ success: false, verified: false }` 반환(Fail-Closed). 공식 OAuth + `/v2/checkout/orders/{orderID}` 조회를 통해 `COMPLETED` 상태, 캡처 `COMPLETED`, 서버 카탈로그 금액·통화(`USD`), 수취인(`merchant_id`/`email`), 중복 주문(`409`) 검증 후 1회용 HMAC `paymentGrantToken` 발급. |
| **작업 02 (P0)** | [webhook/paypal/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/webhook/paypal/route.ts), [securityControls.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/securityControls.ts) | PayPal 공식 5대 서명 헤더(`paypal-transmission-id`, `paypal-transmission-time`, `paypal-cert-url`, `paypal-auth-algo`, `paypal-transmission-sig`) + `PAYPAL_WEBHOOK_ID` 필수화 및 `/v1/notifications/verify-webhook-signature` 검증(`verification_status === "SUCCESS"`). `webhook:{event.id}:{capture.id}` 멱등 키로 중복 재전송 시 1회만 처리. `raw_payload` 및 고객 개인정보 저장 제거(`payload_sha256` 해시만 기록). |
| **작업 03 (P0)** | [firestore.rules](file:///C:/Users/user/Desktop/global-letters/firestore.rules) | 기본 전면 거부(`allow read, write: if false;`) 적용. `payments`/`verified_orders`/`webhook_events`는 관리자(`request.auth.token.admin == true`)만 허용, `letters`/`consultations`는 본인(`ownerUid == request.auth.uid`) 또는 관리자만 허용, `reviews`는 공개 조회 + 인증 사용자 스키마 검증 생성만 허용. |
| **작업 04 (P1)** | [cleanup/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/cleanup/route.ts), [setup-assistant/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/setup-assistant/route.ts), [setup-master/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/setup-master/route.ts), [upload-knowledge/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/upload-knowledge/route.ts), [send-gift/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/send-gift/route.ts), [admin/page.tsx](file:///C:/Users/user/Desktop/global-letters/src/app/admin/page.tsx) | `GET` 파일 삭제(`unlinkSync`/`rmdirSync`) 및 외부 쓰기 완전 제거(`405`/`401`). 모든 관리 API에 `ADMIN_SECRET_KEY` Bearer 토큰 + `x-admin-role: admin` 검증 강제(기본값 `dev-secret-key-1234` 폴백 제거). `upload-knowledge` 키 누락 시 `success: false`(`503`) 반환. |
| **작업 05 (P1)** | [generate-letter/route.ts](file:///C:/Users/user/Desktop/global-letters/src/app/api/generate-letter/route.ts), [securityControls.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/securityControls.ts) | OpenAI 호출 **이전**에 ① 24KB / 티어별 최대 글자수 초과 시 HTTP `413`, ② 유료 티어 미검증/중복 토큰 시 HTTP `401`/`403`/`409`, ③ 원자적 쿼터·분/일 비용 상한 초과 시 HTTP `429` 차단(동시 50요청 경합 테스트에서 정확히 허용 한도 `N=3`회만 통과, `47`건 `429` 차단), ④ 간접 프롬프트 인젝션 탐지·무력화 및 외부 쓰기 도구 호출 `0회` 보장. |

---

## 3. G1 ~ G5 정보화 문명 6단계 검증 모듈 구현 결과 (작업 06 ~ 10)

- **작업 06 (G1 생산)**: [src/lib/gates/index.ts](file:///C:/Users/user/Desktop/global-letters/src/lib/gates/index.ts) (`G1BriefingEngine`) 및 [scripts/g1_apps_script_briefing.gs](file:///C:/Users/user/Desktop/global-letters/scripts/g1_apps_script_briefing.gs) 구현. `run_id`, UTC/KST 시작·종료 시각, HTTP 상태, API 호출수, 재시도 횟수, `media_id + observed_bucket + source` 유일키 기반 중복 방지(`동일 run_id 재실행 시 중복 0건`), 실패 시 `QUEUED_FOR_RETRY -> RECOVERED` 상태 전이 검증 완료. (단, 실제 Google Drive 내 Apps Script 원본 프로젝트는 외부 클라우드 권한 영역이므로 로컬 참조 코드로 제공하며 원본 상태는 `원본 접근 불가`로 정직하게 분류.)
- **작업 07 (G2 AI 품질)**: `evaluateGoldenSet15()`를 통해 Golden Set 15건 전수 재현(`15/15 PASS`), 간접 프롬프트 인젝션 4건 외부 쓰기 `0회`, 금지어(`조용히`/뇌과학 용어 본문 침투/허위 임상 진단·재회 보장/존비어 혼용) 및 후킹 제목 충돌 필터 검증 완료. (실제 외부 블라인드 평가자 검수 전이므로 판정은 규칙에 따라 **`모의 통과 (독립평가 대기)`** 로 기록.)
- **작업 08 (G3 성과 피드백)**: `G3PerformanceLedger`를 통해 `planned_at`, `observed_at`, `platform_source_time`, `ingested_at` 4대 시각 분리, 과거 `71h57m32s` 관측치의 조기 실행(`APPROXIMATE_EARLY`, `-148초`) 자동 판별, 과거 관측치 덮어쓰기 차단(`0건`), `null` vs `0` 엄격 분리, 24h+72h 쌍과 차기 게시물 개선 가설·승인·후속 게시물 링크 검증 완료.
- **작업 09 (G4 복구)**: `runG4ChaosAndRecoverySuite()`를 통해 `PATH=""`(OS `python` 실행 파일 완전 부재) 상태에서도 Node.js RAG·공감 엔진 정상 작동 확인, 장애 주입 후 스냅샷 복원 시 중복 `0건` 및 원장 1:1 정합성(`RPO = 0`, `RTO = 1ms`) 검증 완료.
- **작업 10 (G5 승인 통제)**: `G5ActionControlGate`를 통해 승인 없는 공개 게시·댓글·DM·메일·결제·삭제 실행 `0회`, 타 액션 승인 토큰 재사용 `0회`, 변조된 payload/만료 승인 `0회`, 승인된 `FakeSink` 단 `1회` 실행(동일 nonce 재전송 차단), 비용 임계 초과 시 즉시 중단(`haltedByCostAlert = true`) 검증 완료.
