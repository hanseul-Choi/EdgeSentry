# EdgeSentry — Credential Stuffing Detector 기획 문서

> 최종 업데이트: 2026-09-18
> 상태: 초안 (구현 전, 사용자와 논의하며 계속 구체화 예정)
> 원칙: 처음엔 최소 골격 + 명확한 룰 2~3개로 시작 → 테스트하며 이슈 발견 시 룰/모듈을 점진적으로 보강

---

## 1. 목적

로그인(인증) 요청이 들어왔을 때, 이것이 **정상 사용자의 로그인 시도**인지 **자동화된/악의적인 credential stuffing 공격**인지 판단해 위험도 스코어와 판단 근거를 반환하는 엔진.

- 최종 차단/챌린지 여부는 **호출자(로그인 서버 등)가 결정** — 엔진은 판단 재료(스코어, 위험도, 근거)만 제공한다.
- Python 기반, 독립 HTTP 서비스(FastAPI)로 동작.
- 룰 기반으로 시작하고, 필요 시 통계적 스코어링 → ML로 단계적으로 발전시킨다.

---

## 2. 시스템 개요

```
로그인 서버 / API Gateway
      │  POST /v1/detect  (로그인 시도 메타데이터)
      ▼
┌─────────────────────────────┐
│         EdgeSentry           │
│                               │
│  1. 요청 파싱/검증 (schemas)  │
│  2. 상태 조회 (StateStore)    │  ← IP/계정별 최근 이력
│  3. 룰 엔진 실행 (rules/*)    │  ← config/rules.yaml 기준
│  4. 스코어 합산 (scoring)     │
│  5. 상태 갱신                 │
└─────────────────────────────┘
      │  score, risk_level, triggered_rules, reasons
      ▼
   호출자가 allow / challenge / block 결정
```

- 엔진은 **동기·실시간** 응답을 전제로 한다 (로그인 플로우를 막지 않을 정도의 지연 시간).
- 판단에 필요한 상태(짧은 시간 내 시도 횟수 등)는 엔진 내부에서 관리한다.

---

## 3. 입력 데이터 (요청 스키마)

호출자가 아래 정보를 넘겨준다고 가정한다. 전부 필수는 아니며, 없는 필드는 관련 룰이 스킵되도록 설계한다(가용 데이터가 늘어날수록 자연히 탐지력이 좋아지는 구조).

| 카테고리 | 필드 예시 |
|---|---|
| 기본 요청 정보 | `ip`, `user_agent`, `timestamp`, `account_id`(또는 해시), `login_result`(success/fail), `endpoint` |
| 디바이스/브라우저 지문 | `device_fingerprint_hash`, `header_order_hash`, (가능하면) TLS/JA3 |
| 세션/이력 | `session_id`, `cookie_id`, 클라이언트가 넘겨주는 과거 로그인 이력 요약(선택) |
| 지리/네트워크 | `geo_country`, `geo_city`, `asn`, `is_known_proxy_vpn_dc`(IP reputation 플래그) |

> ⚠️ 열린 질문: 디바이스 지문은 클라이언트(브라우저)에서 별도 JS로 수집해야 넘겨줄 수 있음. 현재 그런 수집 파이프라인이 있는지 확인 필요 → 없다면 1단계에서는 device fingerprint 관련 룰은 제외하고 시작.
> ⚠️ 열린 질문: GeoIP/IP reputation 데이터 소스(MaxMind, 자체 DB, 외부 API 등) 미정 → 1단계에서는 이 필드가 없을 때를 기본값으로 가정.

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
- 상태 저장소는 `StateStore` 인터페이스로 추상화 (1단계: in-memory 구현체 / 이후: Redis 등으로 교체 가능하도록).

### 5-1. 1단계 스타터 룰 후보 (가장 신호가 명확한 것부터)

| 룰 ID | 설명 | 필요 데이터 |
|---|---|---|
| `ip_high_velocity` | 짧은 시간(예: 60s) 내 동일 IP에서 비정상적으로 많은 로그인 시도 | ip, timestamp |
| `account_high_failure` | 짧은 시간 내 동일 계정에 대한 로그인 실패가 반복 | account_id, login_result, timestamp |
| `ip_account_fanout` | 동일 IP가 짧은 시간 내 서로 다른 다수 계정으로 로그인 시도 (스프레이 공격 시그니처) | ip, account_id, timestamp |

### 5-2. 2단계 이후 보강 후보

| 룰 ID | 설명 | 필요 데이터 |
|---|---|---|
| `known_proxy_vpn_dc` | 알려진 프록시/VPN/데이터센터 IP에서의 시도 | is_known_proxy_vpn_dc |
| `impossible_travel` | 짧은 시간 내 물리적으로 불가능한 국가 간 이동 | geo_country, account_id, timestamp |
| `device_fingerprint_anomaly` | 동일 계정에 비정상적으로 많은 디바이스 지문이 붙거나, 자동화 툴 시그니처 UA | device_fingerprint_hash, user_agent |
| `mechanical_timing` | 요청 간격의 variance가 비정상적으로 낮음(스크립트성 패턴) | timestamp 시계열 |

> 구현은 1단계 룰부터: 골격을 만들고 테스트 시나리오(정상 사용자 vs 공격 시나리오)로 검증한 뒤, 이슈가 보이는 지점 위주로 2단계 룰을 하나씩 추가한다.

---

## 6. 모듈 구조 (초안)

```
EdgeSentry/
├── PLAN.md
├── app/
│   ├── api/            # FastAPI 라우터 (POST /v1/detect 등)
│   ├── core/
│   │   ├── rules_engine.py   # 룰 실행/스코어 합산
│   │   ├── rules/             # 룰 1개 = 파일 1개
│   │   │   ├── ip_high_velocity.py
│   │   │   ├── account_high_failure.py
│   │   │   └── ip_account_fanout.py
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

1. **1단계**: 스키마 + `rules_engine` 골격 + 스타터 룰 3개 + in-memory `StateStore`
2. **테스트**: pytest로 룰별 단위 테스트 + 시나리오 테스트(정상 사용자 트래픽 fixture, credential stuffing 공격 fixture)를 먼저 작성해 룰이 의도대로 동작하는지 검증
3. **린트/타입체크**: ruff + mypy (제안 — 확정 필요)
4. **2단계**: 테스트하며 발견한 놓친 패턴/오탐 이슈를 기준으로 룰 보강 (5-2 후보군에서 우선순위 결정)
5. **이후**: 상태 저장소를 Redis 등으로 교체(인터페이스는 유지), 필요 시 통계적 스코어링/ML 단계로 확장

---

## 8. 열린 질문 (구현 전 확정 필요)

- [ ] 디바이스 지문 수집 파이프라인 존재 여부 (없으면 1단계에서 제외)
- [ ] GeoIP/IP reputation 데이터 소스
- [ ] 린트/타입체크 도구 확정 (ruff/mypy 제안)
- [ ] `risk_level` 임계값 초기값 (score → LOW/MEDIUM/HIGH 매핑)
- [ ] 1단계 스타터 룰 3개의 구체적 임계값(예: "60초 내 몇 회부터 high velocity로 볼지")
