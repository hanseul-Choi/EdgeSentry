# EdgeSentry — Credential Stuffing & Automated Abuse Detector

EdgeSentry는 로그인/인증 요청 시 발생하는 메타데이터를 실시간으로 분석하여 **정상 로그인 시도**인지 **자동화된 Credential Stuffing / 무차별 대입(Brute Force) 공격**인지 판별하고, 위험도 점수(`score: 0-100`)와 판단 근거(`triggered_rules`)를 반환하는 탐지 엔진입니다.

- **분리된 책임 구조**: 최종 차단/챌린지 여부는 **호출자(로그인 서버/API Gateway)**가 결정하며, EdgeSentry는 정밀한 판단 재료(Score, Risk Level, Triggered Rules)를 동기/저지연으로 제공합니다.
- **룰 기반 엔진**: 코드 수정 없이 `app/config/rules.yaml` 설정 파일만으로 임계값과 가중치를 유연하게 튜닝할 수 있습니다.
- **추상화된 상태 레이어**: 현재 고성능 인메모리 슬라이딩 윈도우(`MemoryStateStore`)를 제공하며, 향후 분산 환경(Redis 등)으로 확장이 용이합니다.

---

## 1. 아키텍처 및 연동 흐름

```
[클라이언트/브라우저]
       │
       ▼  (1) POST /api/login (아이디, 비밀번호)
[인증/로그인 서버 또는 API Gateway]
       │
       │  (2) POST /v1/detect (IP, 계정ID, 시각, User-Agent 등)
       ▼
┌─────────────────────────────────────────────────────────────┐
│                      EdgeSentry Engine                      │
│                                                             │
│ 1. 스키마 검증 (DetectRequest)                              │
│ 2. 최근 이력 상태 조회 (StateStore 슬라이딩 윈도우)         │
│ 3. 활성화된 룰 평가 (rules/*)                               │
│ 4. 스코어 합산 및 위험도 판정 (LOW / MEDIUM / HIGH)        │
│ 5. 상태 갱신 (현재 시도 이력 저장)                          │
└─────────────────────────────────────────────────────────────┘
       │
       │  (3) DetectResponse (score, risk_level, triggered_rules)
       ▼
[인증/로그인 서버]
       │
       │  (4) 위험도 기반 정책 결정
       │      - LOW    -> 로그인 인증 처리 진행 (Allow)
       │      - MEDIUM -> 추가 인증/CAPTCHA/OTP 요구 (Challenge)
       │      - HIGH   -> 요청 차단 (Block / Rate Limit)
       ▼
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

## 3. 상세 사용 가이드 (How to Use)

### 3-1. 호출 시점 권장 패턴

EdgeSentry는 **사전 평가(Pre-auth)** 또는 **사후 기록(Post-auth)** 방식으로 연동할 수 있습니다:

1. **사전 평가 (Pre-auth Evaluation)**:
   - 로그인 비밀번호를 검증하기 **직전**에 EdgeSentry를 호출하여 IP 속도(`ip_high_velocity`) 및 계정 분산 공격(`ip_account_fanout`) 여부를 먼저 확인합니다.
   - 이미 HIGH 위험도인 악성 IP는 DB 패스워드 해시 연산(bcrypt, argon2 등) 부하 없이 조기에 차단(Drop/CAPTCHA)할 수 있습니다.
2. **사후 결과 전송 (Post-auth Result)**:
   - 인증 실패 시 `login_result="failure"`로 전송하여 단일 계정에 대한 비밀번호 대입 공격(`account_high_failure`)을 추적합니다.

---

### 3-2. API 요청 및 응답 명세

#### 엔드포인트: `POST /v1/detect`

#### 요청 필드 (`DetectRequest`)
| 필드명 | 타입 | 필수 여부 | 설명 및 예시 |
|---|---|:---:|---|
| `ip` | string | **필수** | 클라이언트 IP 주소 (`198.51.100.25`) |
| `timestamp` | string (ISO8601) | 선택 | 시도 시각 (미입력 시 서버 UTC 현재 시각 자동 적용) |
| `account_id` | string | 권장 | 로그인 시도 계정 식별자/이메일 (`user@example.com`) |
| `login_result` | string | 권장 | `success` 또는 `failure` |
| `user_agent` | string | 선택 | 브라우저/클라이언트 User-Agent 헤더 |
| `endpoint` | string | 선택 | 호출된 인증 엔드포인트 (`/api/v1/auth/login`) |
| `device_fingerprint_hash`| string | 선택 | 클라이언트 디바이스 지문 해시 |
| `session_id` | string | 선택 | 세션 또는 쿠키 식별자 |
| `geo_country` | string | 선택 | 2자리 국가 코드 (`KR`, `US`) |
| `is_known_proxy_vpn_dc` | boolean | 선택 | VPN/프록시/데이터센터 IP 여부 |

#### 응답 필드 (`DetectResponse`)
```json
{
  "score": 80,
  "risk_level": "HIGH",
  "triggered_rules": [
    {
      "rule_id": "ip_account_fanout",
      "weight": 45,
      "detail": "6 distinct accounts/60s from IP"
    },
    {
      "rule_id": "ip_high_velocity",
      "weight": 35,
      "detail": "12 attempts/60s from IP"
    }
  ],
  "evaluated_at": "2026-09-18T01:00:00.000000Z"
}
```

---

### 3-3. 클라이언트 연동 예제 코드

#### 1) cURL 예제
```bash
curl -X POST http://localhost:8000/v1/detect \
  -H "Content-Type: application/json" \
  -d '{
    "ip": "203.0.113.195",
    "account_id": "victim_user@company.com",
    "login_result": "failure",
    "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "endpoint": "/v1/auth/login"
  }'
```

#### 2) Python (FastAPI / Flask / Django 로그인 서버 연동 예시)
```python
import httpx
from fastapi import HTTPException, status

EDGESENTRY_URL = "http://localhost:8000/v1/detect"

async def check_login_risk(client_ip: str, account_id: str) -> str:
    """로그인 서버 내부에서 EdgeSentry를 호출하여 위험도 평가."""
    payload = {
        "ip": client_ip,
        "account_id": account_id,
        "endpoint": "/api/v1/login"
    }
    
    async with httpx.AsyncClient(timeout=0.5) as client:  # 타임아웃 500ms 권장
        try:
            response = await client.post(EDGESENTRY_URL, json=payload)
            data = response.json()
            risk_level = data.get("risk_level", "LOW")
            score = data.get("score", 0)
            
            # 정책에 따른 액션 분기
            if risk_level == "HIGH":
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="비정상적인 접근이 감지되어 로그인이 일시적으로 제한되었습니다."
                )
            elif risk_level == "MEDIUM":
                # CAPTCHA 또는 2FA 인증 요구 플래그 반환
                return "REQUIRE_CAPTCHA"
            
            return "ALLOW"
        except httpx.RequestError:
            # 장애 격리: EdgeSentry 응답 실패 시 정상 로그인 플로우를 막지 않도록 Fail-Open 전략 권장
            return "ALLOW"
```

#### 3) Node.js (Express 예시)
```javascript
const axios = require('axios');

async function evaluateRisk(req, accountId) {
  try {
    const res = await axios.post('http://localhost:8000/v1/detect', {
      ip: req.ip || req.headers['x-forwarded-for'],
      account_id: accountId,
      user_agent: req.headers['user-agent'],
      endpoint: req.originalUrl
    }, { timeout: 500 });

    const { risk_level, score } = res.data;
    return risk_level; // 'LOW' | 'MEDIUM' | 'HIGH'
  } catch (err) {
    // Fail-Open 전략
    console.error('EdgeSentry evaluation failed, defaulting to LOW', err.message);
    return 'LOW';
  }
}
```

---

## 4. 룰 및 위험도 임계값 커스터마이징 (`rules.yaml`)

모든 임계값과 가중치는 [app/config/rules.yaml](file:///Users/choehanseul/work/EdgeSentry/app/config/rules.yaml)에서 설정할 수 있습니다.

```yaml
# 위험도 판정 기준 (0~100점)
risk_thresholds:
  medium: 40  # 40점 이상 -> MEDIUM
  high: 70    # 70점 이상 -> HIGH

rules:
  # 1. 단일 IP 과도 요청 탐지
  ip_high_velocity:
    enabled: true
    weight: 35
    window_seconds: 60  # 60초 윈도우
    threshold: 10       # 10회 이상 시도 시 트리거

  # 2. 단일 계정 반복 실패 탐지 (무차별 대입)
  account_high_failure:
    enabled: true
    weight: 40
    window_seconds: 60
    threshold: 5        # 5회 이상 실패 시 트리거

  # 3. 단일 IP 다수 계정 분산 시도 탐지 (스프레이/Stuffing)
  ip_account_fanout:
    enabled: true
    weight: 45
    window_seconds: 60
    threshold: 5        # 5개 이상 고유 계정 시도 시 트리거
```

---

## 5. 테스트 및 코드 품질 검사

```bash
# 전체 테스트 실행 (21개 테스트: 단위, 상태 저장소, 시나리오, API)
.venv/bin/pytest tests/ -v

# 린트 및 포맷 검사
.venv/bin/ruff check .

# 타입 정적 검사
.venv/bin/mypy app
```
