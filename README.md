# EdgeSentry — Credential Stuffing & Automated Abuse Detector

EdgeSentry는 로그인/인증 요청 시 발생하는 메타데이터를 실시간으로 분석하여 **정상 로그인 시도**인지 **자동화된 Credential Stuffing / 무차별 대입(Brute Force) 공격**인지 판별하고, 위험도 점수(`score: 0-100`)와 판단 근거(`triggered_rules`)를 반환하는 탐지 엔진입니다.

---

## 1. 주요 기능

- **실시간 탐지 (FastAPI)**: 동기·저지연 HTTP API (`POST /v1/detect`)
- **YAML 기반 룰 설정**: 임계값, 시간 윈도우, 가중치를 코드 배포 없이 `app/config/rules.yaml`에서 손쉽게 조정
- **추상화된 상태 관리 (`StateStore`)**: 인메모리 슬라이딩 윈도우(`MemoryStateStore`) 지원 (향후 Redis 등으로 교체 가능)
- **1단계 핵심 탐지 룰**:
  - `ip_high_velocity`: 단일 IP 기준 짧은 시간 내 과도한 로그인 시도 탐지
  - `account_high_failure`: 동일 계정 대상 연속적인 로그인 실패 탐지
  - `ip_account_fanout`: 단일 IP에서 다수 계정으로 시도하는 스프레이(Spray) 공격 탐지

---

## 2. 프로젝트 구조

```
EdgeSentry/
├── PLAN.md                    # 전체 프로젝트 기획 문서
├── README.md                  # 사용 및 개발 가이드
├── pyproject.toml             # 의존성 및 프로젝트 메타데이터
├── app/
│   ├── __init__.py
│   ├── main.py                # FastAPI 앱 엔트리포인트
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py          # /v1/detect, /health 라우터
│   ├── config/
│   │   ├── __init__.py
│   │   ├── rules.yaml         # 룰 및 위험도 임계값 설정
│   │   └── settings.py        # YAML 설정 로더 및 Pydantic 유효성 검증
│   ├── core/
│   │   ├── __init__.py
│   │   ├── rules_engine.py    # 룰 평가 오케스트레이션 및 스코어 합산
│   │   ├── rules/             # 개별 룰 모듈
│   │   │   ├── base.py
│   │   │   ├── ip_high_velocity.py
│   │   │   ├── account_high_failure.py
│   │   │   └── ip_account_fanout.py
│   │   └── state/             # 상태 저장소 인터페이스 및 구현
│   │       ├── base.py
│   │       └── memory_store.py
│   └── schemas/
│       ├── __init__.py
│       └── detection.py       # Pydantic 입출력 스키마
└── tests/
    ├── conftest.py
    ├── test_api/              # HTTP 엔드포인트 통합 테스트
    ├── test_rules/            # 룰별 단위 테스트
    ├── test_scenarios/        # 정상 / 스프레이 / 무차별 대입 공격 시나리오 테스트
    └── test_state/            # 슬라이딩 윈도우 상태 저장소 테스트
```

---

## 3. 시작하기

### 설치 및 가상환경 구성
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 서버 실행
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 4. API 사용법

### 1) 탐지 요청 (`POST /v1/detect`)

**요청 본문 예시:**
```json
{
  "ip": "198.51.100.25",
  "account_id": "alice@example.com",
  "login_result": "failure",
  "user_agent": "Mozilla/5.0 ...",
  "endpoint": "/v1/auth/login"
}
```

**응답 예시 (정상):**
```json
{
  "score": 0,
  "risk_level": "LOW",
  "triggered_rules": [],
  "evaluated_at": "2026-09-18T00:40:00.000000Z"
}
```

**응답 예시 (공격 의심 시):**
```json
{
  "score": 80,
  "risk_level": "HIGH",
  "triggered_rules": [
    {
      "rule_id": "ip_high_velocity",
      "weight": 35,
      "detail": "10 attempts/60s from IP"
    },
    {
      "rule_id": "ip_account_fanout",
      "weight": 45,
      "detail": "8 distinct accounts/60s from IP"
    }
  ],
  "evaluated_at": "2026-09-18T00:40:15.000000Z"
}
```

### 2) 헬스체크 (`GET /health`, `GET /v1/health`)
```bash
curl http://localhost:8000/health
```

---

## 5. 테스트 및 정적 분석

### 테스트 실행
```bash
.venv/bin/pytest tests/ -v
```

### 린트 및 코드 스타일 검사
```bash
.venv/bin/ruff check .
```

### 타입 검사
```bash
.venv/bin/mypy app
```
