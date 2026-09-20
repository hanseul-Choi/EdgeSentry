# EdgeSentry — Login Abuse Detector 기획 문서

> 최종 업데이트: 2026-09-20
> 상태: 초안 v2 (범위를 "로그인 시점 abuse"로 한정. 코드 반영 전 사용자 확인 필요)
> 원칙: 처음엔 최소 골격 + 명확한 룰로 시작 → 테스트하며 이슈 발견 시 룰/모듈을 점진적으로 보강

---

## 1. 목적과 범위

### 1-1. 목적

**로그인(인증) 시점**에 발생하는 abuse를 탐지한다. 로그인 시도가 정상 사용자의 것인지, 아래 공격 유형에 해당하는지 판단해 위험도 스코어와 판단 근거를 반환하는 엔진.

- 최종 차단/챌린지 여부는 **호출자(로그인 서버 등)가 결정** — 엔진은 판단 재료(스코어, 위험도, 근거)만 제공한다.
- Python 기반, 독립 HTTP 서비스(FastAPI)로 동작.
- 룰 기반으로 시작하고, 필요 시 통계적 스코어링 → ML로 단계적으로 발전시킨다.

### 1-2. 탐지 대상 공격 유형

| 공격 유형 | 시그니처 | 대응 룰 |
|---|---|---|
| Credential stuffing | 유출된 계정 목록으로 한 IP가 여러 계정에 시도 | `ip_account_fanout` |
| Brute force | 한 계정에 비밀번호를 바꿔가며 반복 실패 | `account_high_failure`, `ip_high_velocity` |
| Password spraying | 흔한 비밀번호 하나로 다수 계정을 저속으로 시도 | `ip_account_fanout` (긴 윈도우 설정) |
| 실패 후 성공 (탈취 의심) | 실패가 누적된 계정이 뒤이어 로그인에 성공 | `success_after_failures` (신규) |

### 1-3. 범위 밖 (이 프로젝트에서 다루지 않음)

- 로그인 이후 세션/행위 기반 탐지 (impossible travel 등 계정 탈취 후 행위 분석)
- 로그인 외 엔드포인트의 범용 봇 탐지
- 디바이스 지문, IP reputation(VPN/프록시/데이터센터), GeoIP 기반 탐지

> 위 항목은 로그인 abuse 탐지와 데이터 수집 요건이 달라 범위를 흐리므로 기획에서 제외한다. 필요해지면 별도 기획으로 다룬다.

---

## 2. 시스템 개요

로그인 플로우에서 EdgeSentry를 **두 번, 역할을 나눠** 호출한다.

```
로그인 서버 / API Gateway
      │
      │ (1) POST /v1/login/check   ← 비밀번호 검증 전, 조회만 (상태 기록 없음)
      ▼
┌──────────────────────────────┐
│         EdgeSentry            │
│  요청 검증 → 상태 조회 → 룰 평가 → 스코어 │
└──────────────────────────────┘
      │  score, risk_level, triggered_rules
      ▼
로그인 서버: 위험도에 따라 allow / challenge / block
      │  (차단되지 않은 경우 비밀번호 검증 수행)
      │
      │ (2) POST /v1/login/report  ← 인증 결과 확정 후, 기록 + 결과 기반 룰 평가
      ▼
┌──────────────────────────────┐
│         EdgeSentry            │
│  요청 검증 → 상태 조회 → 룰 평가 → 스코어 → 상태 기록 │
└──────────────────────────────┘
```

- **check**: 사전 차단용. 이미 HIGH인 IP는 비밀번호 해시 연산(bcrypt 등) 전에 걸러낸다. 상태를 기록하지 않으므로 report와 이중 카운트되지 않는다.
- **report**: 로그인 결과(`success`/`failure`)를 기록한다. 실패 카운트와 `success_after_failures` 같은 결과 기반 룰은 이 단계에서 평가한다.
- 엔진은 **동기·실시간** 응답을 전제로 한다 (로그인 플로우를 막지 않을 정도의 지연 시간). 호출 실패 시 fail-open 권장.
- 판단에 필요한 상태(짧은 시간 내 시도 횟수 등)는 엔진 내부에서 관리한다.

---

## 3. 입력 데이터 (요청 스키마)

룰이 실제로 사용하는 필드만 정의한다.

| 필드 | check | report | 용도 |
|---|:---:|:---:|---|
| `ip` | 필수 | 필수 | IP 단위 룰의 키 |
| `account_id` | 권장 | 권장 | 계정 단위 룰의 키 (원문 대신 해시 전달 권장) |
| `timestamp` | 선택 | 선택 | 미입력 시 서버 UTC 현재 시각 |
| `login_result` | — | 필수 | `success` / `failure` |

- 없는 필드는 관련 룰이 스킵된다 (예: `account_id`가 없으면 계정 단위 룰은 평가하지 않음).
- `user_agent`는 현재 룰이 사용하지 않으므로 선택 필드로만 두고, 룰 추가 시 그때 사용 여부를 정한다.

---

## 4. 출력 스키마

```json
{
  "score": 0-100,
  "risk_level": "LOW | MEDIUM | HIGH",
  "triggered_rules": [
    {"rule_id": "ip_high_velocity", "weight": 30, "detail": "10 attempts/60s from IP"}
  ],
  "evaluated_at": "ISO8601 timestamp"
}
```

액션(allow/challenge/block)은 포함하지 않는다 — 호출자가 `risk_level`/`score`를 보고 자체 정책으로 결정.

---

## 5. 룰 엔진 설계

- 룰은 **YAML 설정 파일**(`config/rules.yaml`)로 정의: 임계값, 가중치를 코드 수정 없이 조정 가능.
- 각 룰은 독립 모듈로 구현하고, 룰 엔진이 순회하며 실행 → 트리거된 룰의 가중치를 합산해 스코어 산출.
- 각 룰은 자신이 평가되는 단계(`check` / `report` / 둘 다)를 선언한다.
- 상태 저장소는 `StateStore` 인터페이스로 추상화 (1단계: in-memory 구현체 / 이후: Redis 등으로 교체 가능하도록).

### 5-1. 룰 목록

| 룰 ID | 설명 | 평가 단계 | 필요 데이터 | 상태 |
|---|---|---|---|---|
| `ip_high_velocity` | 짧은 시간 내 동일 IP에서 비정상적으로 많은 로그인 시도 | check, report | ip | 구현됨 |
| `account_high_failure` | 짧은 시간 내 동일 계정에 대한 로그인 실패 반복 | check, report | account_id, login_result | 구현됨 |
| `ip_account_fanout` | 동일 IP가 짧은 시간 내 다수의 서로 다른 계정으로 시도 | check, report | ip, account_id | 구현됨 |
| `success_after_failures` | 실패가 N회 이상 누적된 계정에 로그인 성공 (IP 무관) | report | account_id, login_result | **신규** |

### 5-2. 이후 보강 후보 (로그인 abuse 범위 내)

| 룰 ID | 설명 | 비고 |
|---|---|---|
| `account_distributed_failure` | 여러 IP에서 한 계정으로 분산된 실패 | 분산 brute force 대응 |
| `ip_high_failure_ratio` | IP 단위 로그인 실패율이 비정상적으로 높음 | 성공률이 낮은 stuffing 대응 |
| `spray_long_window` | 긴 윈도우(예: 1시간)에서 저속 fanout | password spraying 대응. `ip_account_fanout`에 윈도우를 추가하는 방식도 가능 |

> 구현은 1단계 룰부터: 골격을 만들고 테스트 시나리오(정상 사용자 vs 공격 시나리오)로 검증한 뒤, 이슈가 보이는 지점 위주로 후보 룰을 하나씩 추가한다.

---

## 6. 모듈 구조 (초안)

```
EdgeSentry/
├── PLAN.md
├── app/
│   ├── api/            # FastAPI 라우터 (POST /v1/login/check, /v1/login/report)
│   ├── core/
│   │   ├── rules_engine.py   # 룰 실행/스코어 합산 (check/report 모드 지원)
│   │   ├── rules/             # 룰 1개 = 파일 1개
│   │   │   ├── ip_high_velocity.py
│   │   │   ├── account_high_failure.py
│   │   │   ├── ip_account_fanout.py
│   │   │   └── success_after_failures.py
│   │   └── state/
│   │       ├── base.py        # StateStore 인터페이스
│   │       └── memory_store.py
│   ├── schemas/         # pydantic 입출력 모델
│   └── config/
│       └── rules.yaml
└── tests/
    ├── test_rules/       # 룰별 단위 테스트
    └── test_scenarios/   # 정상/공격 시나리오 통합 테스트
```

각 룰이 독립 모듈이므로, 새 룰 추가/기존 룰 조정이 다른 코드에 영향을 주지 않도록 한다.

---

## 7. 개발·검증 전략 (반복 보강)

1. **1단계**: check/report API 분리 + 룰 엔진 모드 지원 + `success_after_failures` 추가
2. **테스트**: pytest로 룰별 단위 테스트 + 시나리오 테스트(정상 사용자, stuffing, brute force, spraying, 실패 후 성공)를 먼저 작성해 검증
3. **린트/타입체크**: ruff + mypy (이미 프로젝트에 적용됨)
4. **2단계**: 테스트하며 발견한 놓친 패턴/오탐 이슈를 기준으로 5-2 후보 룰 보강
5. **이후**: 상태 저장소를 Redis 등으로 교체(인터페이스는 유지), 필요 시 통계적 스코어링/ML 단계로 확장

---

## 8. 열린 질문

- [ ] `success_after_failures`의 초기 임계값 (예: 10분 윈도우 내 실패 N회 이상 후 성공)
- [ ] password spraying 대응: 기존 `ip_account_fanout`에 긴 윈도우를 추가할지, 별도 룰로 분리할지
- [ ] 기존 `POST /v1/detect`를 유지할지(하위 호환), `check`/`report`로 완전히 교체할지
- [ ] `check` 단계에서 "현재 시도"를 카운트에 포함할지 (report와 임계값 기준을 어떻게 맞출지)
- [ ] `risk_level` 임계값 초기값 (현재 medium 40 / high 70)
- [ ] 스키마에서 룰이 사용하지 않는 필드(`device_fingerprint_hash`, `header_order_hash`, `cookie_id`, `geo_*`, `asn`, `is_known_proxy_vpn_dc`, `session_id`)를 코드에서 제거할지

---

## 9. 변경 이력

- 2026-09-20 (v2): 범위를 로그인 abuse로 한정. 공격 유형 4종 정의, 범위 밖 항목(impossible_travel, mechanical_timing, device_fingerprint, IP reputation/GeoIP) 삭제, check/report 분리 호출 방식 도입, `success_after_failures` 룰 추가.
- 2026-09-18 (v1): 초기 기획 (credential stuffing 탐지).
