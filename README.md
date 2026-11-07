# EdgeSentry — Login Abuse Detector

EdgeSentry는 로그인(인증) 시점에 발생하는 메타데이터를 실시간으로 분석하여 **정상 로그인 시도**인지 **악의적인 어뷰징 공격(Credential Stuffing, Brute Force, Password Spraying, 실패 누적 후 계정 탈취)**인지 판별하고, 위험도 점수(`score: 0-100`)와 판단 근거(`triggered_rules`)를 반환하는 경량 탐지 엔진입니다.

- **분리된 책임 구조**: 최종 차단/챌린지 여부는 **호출자(로그인 서버/API Gateway)**가 결정하며, EdgeSentry는 정밀한 판단 재료(Score, Risk Level, Triggered Rules)를 동기/저지연으로 제공합니다.
- **Check / Report 이원화 아키텍처**:
  1. 비밀번호 검증 전 사전 차단용 `POST /v1/login/check` (상태 미기록, bcrypt 부하 방지)
  2. 비밀번호 검증 후 결과 보고용 `POST /v1/login/report` (상태 기록 및 결과 기반 룰 평가)
- **룰 기반 엔진**: 코드 수정 없이 `app/config/rules.yaml` 설정 파일만으로 임계값과 가중치를 유연하게 튜닝할 수 있습니다.
- **추상화된 상태 레이어**: 고성능 인메모리 슬라이딩 윈도우(`MemoryStateStore`)를 제공하며, 향후 분산 환경(Redis 등)으로 확장이 용이합니다.

---

## 1. 아키텍처 및 2단계 연동 흐름

```
[클라이언트/브라우저]
       │
       ▼  (1) POST /api/login (아이디, 비밀번호)
[인증/로그인 서버 또는 API Gateway]
       │
       │  (2) POST /v1/login/check (IP, 계정ID, 시각 등)
       ▼      * 상태 기록 없음 (Pre-auth, 이중 카운팅 방지)
┌─────────────────────────────────────────────────────────────┐
│                 EdgeSentry Engine (Check)                   │
│                                                             │
│ 1. 스키마 검증 (LoginCheckRequest)                          │
│ 2. 최근 이력 상태 조회 (StateStore 슬라이딩 윈도우)         │
│ 3. 활성화된 Check 룰 평가 (ip_velocity, ip_fanout, failure) │
│ 4. 스코어 합산 및 위험도 판정 (LOW / MEDIUM / HIGH)        │
└─────────────────────────────────────────────────────────────┘
       │
       │  (3) DetectResponse (score, risk_level, triggered_rules)
       ▼
[인증/로그인 서버]
       │
       ├─ HIGH   ──> [즉시 차단 / 429 반환] (비밀번호 검증 부하 방지)
       ├─ MEDIUM ──> [CAPTCHA / MFA 요구]
       └─ LOW    ──> 비밀번호 해시 검증(bcrypt) 수행
                      │
       ┌──────────────┴──────────────┐
       ▼                             ▼
   인증 성공 (success)           인증 실패 (failure)
       │                             │
       └──────────────┬──────────────┘
                      │
       (4) POST /v1/login/report (IP, 계정ID, login_result)
       ▼   * 상태 기록 및 사후 룰(success_after_failures 등) 평가
┌─────────────────────────────────────────────────────────────┐
│                EdgeSentry Engine (Report)                   │
│                                                             │
│ 1. 스키마 검증 (LoginReportRequest)                         │
│ 2. 사후 룰 평가 (예: 실패 누적 후 성공 탈취 의심 탐지)      │
│ 3. 상태 저장소 이력 기록 (StateStore.record_attempt)        │
└─────────────────────────────────────────────────────────────┘
       │
       ▼ (5) 최종 로그인 결과 반환 (클라이언트에게 성공/실패 응답)
[클라이언트/브라우저]
```

---

## 2. 빠른 시작 (Getting Started)

### 환경 요구사항
- Python 3.11 이상

### 설치 및 가상환경 구성
```bash
# 가상환경 생성 및 활성화
python3 -m venv .venv
source .venv/bin/activate

# 의존성 패키지 설치 (개발/테스트 도구 포함)
pip install -e ".[dev]"
```

### 서버 기동
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
서버가 정상 구동되면 `http://localhost:8000/docs`에서 대화형 Swagger API 문서를 확인할 수 있습니다.

---

## 3. API 엔드포인트 명세

### 3-1. 사전 검사: `POST /v1/login/check`
비밀번호 해시 검증 전에 호출하여 악성 IP 또는 무차별 대입 대상 계정인지 사전 확인합니다. **상태를 기록하지 않으므로 이중 카운팅되지 않습니다.**

- **요청 Body (`LoginCheckRequest`)**:
  ```json
  {
    "ip": "203.0.113.195",
    "account_id": "user@example.com",
    "timestamp": "2026-09-20T12:00:00Z"
  }
  ```

### 3-2. 사후 결과 보고: `POST /v1/login/report`
비밀번호 검증 후 성공/실패 결과를 전달하여 상태 저장소에 이력을 갱신하고, 실패 누적 후 성공 등 결과 기반 룰을 평가합니다.

- **요청 Body (`LoginReportRequest`)**:
  ```json
  {
    "ip": "203.0.113.195",
    "account_id": "user@example.com",
    "login_result": "success",
    "timestamp": "2026-09-20T12:00:01Z"
  }
  ```

### 3-3. 공통 응답 포맷 (`DetectResponse`)
```json
{
  "score": 50,
  "risk_level": "MEDIUM",
  "triggered_rules": [
    {
      "rule_id": "success_after_failures",
      "weight": 50,
      "detail": "Login success after 3 failed attempts/600s for account"
    }
  ],
  "evaluated_at": "2026-09-20T12:00:01.000000Z"
}
```

> 💡 **하위 호환 지원**: 기존 단일 호출 엔드포인트인 `POST /v1/detect`도 계속 지원됩니다 (report 모드로 동작).

---

## 4. 클라이언트 연동 예제 (Python FastAPI / httpx)

```python
import httpx
from fastapi import HTTPException, status

EDGESENTRY_CHECK_URL = "http://localhost:8000/v1/login/check"
EDGESENTRY_REPORT_URL = "http://localhost:8000/v1/login/report"

async def login_flow(client_ip: str, account_id: str, password: str):
    async with httpx.AsyncClient(timeout=0.5) as client:
        # Step 1: Pre-auth check (사전 차단)
        try:
            check_resp = await client.post(
                EDGESENTRY_CHECK_URL,
                json={"ip": client_ip, "account_id": account_id}
            )
            data = check_resp.json()
            if data.get("risk_level") == "HIGH":
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="비정상적인 접근으로 로그인이 일시적으로 차단되었습니다."
                )
        except httpx.RequestError:
            pass  # Fail-Open 전략

        # Step 2: 비밀번호 검증 (실제 DB 인증)
        is_authenticated = verify_password_in_db(account_id, password)
        login_result = "success" if is_authenticated else "failure"

        # Step 3: Post-auth report (결과 기록 및 사후 룰 평가)
        try:
            report_resp = await client.post(
                EDGESENTRY_REPORT_URL,
                json={
                    "ip": client_ip,
                    "account_id": account_id,
                    "login_result": login_result
                }
            )
            report_data = report_resp.json()
            # 예: 성공했으나 탈취 의심(success_after_failures)인 경우 추가 2FA 요구
            if is_authenticated and report_data.get("risk_level") in ("MEDIUM", "HIGH"):
                return {"status": "REQUIRE_2FA_CHALLENGE"}
        except httpx.RequestError:
            pass

        if not is_authenticated:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="아이디 또는 비밀번호가 잘못되었습니다.")

        return {"status": "SUCCESS", "token": "jwt_token_here"}
```

---

## 5. 룰 및 위험도 임계값 커스터마이징 (`rules.yaml`)

모든 임계값과 가중치는 [app/config/rules.yaml](file:///Users/choehanseul/work/EdgeSentry/app/config/rules.yaml)에서 설정할 수 있습니다.

```yaml
# 위험도 판정 기준 (0~100점)
risk_thresholds:
  medium: 40  # 40점 이상 -> MEDIUM
  high: 70    # 70점 이상 -> HIGH

rules:
  # 1. 단일 IP 과도 요청 탐지 (Check & Report)
  ip_high_velocity:
    enabled: true
    weight: 35
    window_seconds: 60  # 60초 윈도우
    threshold: 10       # 10회 이상 시도 시 트리거

  # 2. 단일 계정 반복 실패 탐지 (무차별 대입, Check & Report)
  account_high_failure:
    enabled: true
    weight: 40
    window_seconds: 60
    threshold: 5        # 5회 이상 실패 시 트리거

  # 3. 단일 IP 다수 계정 분산 시도 탐지 (스프레이/Stuffing, Check & Report)
  ip_account_fanout:
    enabled: true
    weight: 45
    window_seconds: 60
    threshold: 5        # 5개 이상 고유 계정 시도 시 트리거

  # 4. 실패 누적 후 성공 탐지 (계정 탈취 의심, Report 전용)
  success_after_failures:
    enabled: true
    weight: 50
    window_seconds: 600 # 10분 윈도우
    threshold: 3        # 직전 10분 내 3회 이상 실패 누적 후 성공 시 트리거
```

---

## 6. 테스트 및 코드 품질 검사

```bash
# 전체 테스트 실행 (31개 테스트: 단위, 상태 저장소, 시나리오, 2단계 플로우 API)
.venv/bin/pytest tests/ -v

# 린트 및 포맷 검사
.venv/bin/ruff check .

# 타입 정적 검사
.venv/bin/mypy app
```
