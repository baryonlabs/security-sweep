# 보안 스윕 보고서

- 생성: 2026-10-23 20:38
- 출력 디렉터리: `/home/dev/security-sweep-20261023-2110`
- 대상: 프로젝트 2, 서버 0, 이미지 0
- OSV 검증: 확인 0 / 404 0 / 미확인 0, KEV: cache, EPSS: 해당 없음

## 요약

| 우선순위 | 건수 | 기준 |
|---|---:|---|
| P0 | 0 | KEV 등재 또는 critical/high + 실제 호출 |
| P1 | 1 | critical/high + import·불명, EPSS ≥ 0.1, 비밀값 |
| P2 | 0 | medium, 또는 high 인데 직접 import 없음 |
| P3 | 0 | low / unknown |
| 검증 실패(OSV 404) | 0 | 우선순위 산정 제외 |

> 도달성 `not-imported` 는 직접 import 를 못 찾았다는 뜻일 뿐이다. 전이 의존성으로 쓰일 수 있으므로 안전을 의미하지 않는다.

## 도구 상태

| 도구 | 상태 | 비고 |
|---|---|---|
| osv-scanner | available | osv-scanner version: 2.7.0 |
| trivy | available | Version: 0.76.1 |
| govulncheck | missing | install: go install golang.org/x/vuln/cmd/govulncheck@latest |
| elixir-security-audit | available | (설치됨) |
| osv-scanner | ok | phoenix-saas-assets: exit 0 (no vulns) |
| osv-scanner | ok | phoenix-saas: exit 0 (no vulns) |
| trivy | ok | phoenix-saas-assets: fs secret,misconfig |
| trivy | ok | phoenix-saas: fs secret,misconfig |

## P0 / P1

| 우선순위 | 대상 | 패키지/종류 | ID | 심각도 | 근거 | 수정 버전 | 위치 |
|---|---|---|---|---|---|---|---|
| P1 | phoenix-saas | 코드 패턴 | EXS-CFG-001 | high |  |  | config/config.exs:36 |

## 대상별 결과

### 프로젝트: phoenix-saas

`/home/dev/projects/phoenix-saas`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 코드 패턴 | 코드 패턴 | EXS-CFG-001 | high | - | n/a |  |  |  | grep | config/config.exs:36 | 비밀 값 하드코딩 (secret_key_base / signing_salt) |

## 검증 실패 (OSV 404)

없음.

## 다음 행동

스윕은 아무것도 수정하지 않았다. 아래 명령은 검토 후 직접 실행한다 (프로젝트별로 브랜치를 만들고 테스트를 돌릴 것).

수정할 취약 의존성 없음.
