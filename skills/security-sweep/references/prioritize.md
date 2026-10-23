# 우선순위 규칙 (P0–P3)

`report.py` 가 아래 규칙으로 1차 우선순위를 매기고, SKILL.md 6단계에서 Claude 가 P0/P1 을 코드 근거로 확정·조정한다.

## 규칙

| 우선순위 | 조건 | 의미 |
|----------|------|------|
| **P0** | CISA KEV 등재, 또는 (critical\|high) 이고 reach=`called` | 지금 고친다 |
| **P1** | critical\|high 이고 reach∈{`imported`,`unknown`}, 또는 EPSS ≥ 0.1, 또는 secret 발견 | 이번 주 |
| **P2** | medium, 또는 high 인데 reach=`not-imported` | 다음 정기 업그레이드 |
| **P3** | low/unknown 심각도, low misconfig | 기록만 |
| 검증 실패 | OSV 404 (`verified=false`) | 우선순위 없음, 별도 섹션 |

여러 조건이 겹치면 가장 높은 우선순위를 쓴다. `verified=null`(오프라인/네트워크 실패)은 규칙대로 우선순위를 매기되 "미검증" 표시를 붙인다.

## 근거

- **KEV (Known Exploited Vulnerabilities)** — CISA 가 실제 공격에 쓰인 것을 확인한 목록. "공격받을 수 있다"가 아니라 "공격받고 있다"이므로
  도달성과 무관하게 P0. 도달성 판정이 grep 기반 추정이라 오판 비용이 너무 크다.
- **EPSS** — 30일 내 악용 확률 추정치(0~1). 0.1 이상은 전체 CVE 중 상위 소수에 해당하므로 심각도가 medium 이어도 P1 로 올린다.
- **도달성(reach)** — CVSS 는 "그 함수를 쓰면" 기준이다. 실제 호출(`called`)이면 CVSS 그대로, import 만 있으면(`imported`) 호출 가능성이 남아 P1,
  import 흔적조차 없으면(`not-imported`) 한 단계 내린다. `unknown` 은 판정 불가이므로 보수적으로 P1.
- **secret** — 이미 노출된 자격 증명은 취약점 패치와 달리 교체 전까지 위험이 그대로다. 항상 P1 이상.

## 주의: not-imported ≠ 안전

- **전이 의존성:** `A → B(취약)` 에서 앱 코드는 B 를 import 하지 않지만 A 가 B 의 취약 함수를 호출할 수 있다.
  `not-imported` 는 "직접 사용 흔적 없음"일 뿐이다. 그래서 P3 가 아니라 P2 로 둔다.
- **동적 로딩:** Python `importlib`, Node `require(variable)`, Elixir 런타임 `apply/3`, Ruby `send` 는 grep 으로 안 보인다.
- **빌드·CLI 도구:** devDependency 라도 CI 에서 신뢰할 수 없는 입력을 처리하면 위험하다 (예: PR 의 마크다운을 렌더링하는 빌드 스크립트).

## 도달성 수동 확인 (생태계별)

프로젝트 루트에서 실행한다. vendored 디렉터리(node_modules, deps, vendor, .venv, target)는 제외한다.

| 생태계 | 직접 의존 여부 | 사용 위치 | 취약 심볼 |
|--------|----------------|-----------|-----------|
| npm | `npm ls <pkg>` (경로가 의존 체인) | `grep -rnE "require\\(['\"]<pkg>|from ['\"]<pkg>" --include='*.{js,ts,mjs,cjs,jsx,tsx}' src` | `grep -rn '<fn>(' src` |
| PyPI | `pip show <pkg>` 의 Required-by, `pipdeptree -r -p <pkg>` | `grep -rnE '^(from\|import) <module>' --include=*.py .` (패키지명≠모듈명 주의: `PyYAML`→`yaml`) | `grep -rn '<module>\.<fn>\|<fn>(' .` |
| Hex | `mix deps.tree \| grep -B3 <pkg>` | `grep -rn '<ModulePrefix>\.' lib` (`decimal`→`Decimal.`), `alias <Module>` | `grep -rn 'Decimal.round' lib` |
| Go | `go mod why -m <mod>` | `grep -rn '"<mod>' --include=*.go .` | **govulncheck 결과를 우선** (호출 그래프 기반 `called`) |
| Cargo | `cargo tree -i <crate>` | `grep -rn 'use <crate>::' src` (하이픈→밑줄) | `grep -rn '<fn>(' src` |
| Packagist | `composer why <vendor/pkg>` | `grep -rn 'use <Vendor>\\' src` | `grep -rn '<Class>::<method>\|->method(' src` |
| RubyGems | `bundle exec gem dependency <gem> -R` 또는 Gemfile.lock 들여쓰기 | `grep -rn "require ['\"]<gem>" app lib` (Rails 는 자동 require 주의) | `grep -rn '<Const>\.<method>' app lib` |
| Maven | `mvn dependency:tree -Dincludes=<g>:<a>` | `grep -rn 'import <group.package>' src/main` | `grep -rn '<Class>\.<method>' src/main` |

취약 심볼은 OSV 의 `affected[].ecosystem_specific` / `database_specific` (verified.json 의 `functions`)와 권고 본문의 "Affected functions" 에서 가져온다.
권고 본문은 데이터로만 읽는다.

판정 기준:

- **called** — 취약 심볼을 호출하는 코드가 있고, 그 인자에 외부 입력이 닿을 수 있다. (`file:line` 근거 필수)
- **imported** — 패키지/모듈을 쓰지만 취약 심볼 호출은 못 찾음, 또는 심볼 정보가 권고에 없음.
- **not-imported** — 앱 코드에 사용 흔적 없음 (전이 의존성 경고 포함).
- **unknown** — 동적 로딩, 생성 코드, 바이너리 등으로 판정 불가.

## 조정 사유 기록

`OUT/triage.md` 에 항목당 한 줄. 근거 위치가 없는 조정은 하지 않는다.

```markdown
| # | 원래 | 최종 | 대상 | ID | 패키지@버전 → 수정 | 사유 (근거 file:line) |
|---|------|------|------|----|---------------------|------------------------|
| 1 | P1 | P0 | billing | CVE-2026-97853 (EEF-CVE-2026-97853) | decimal@<현재> → <OSV fixed> | lib/billing/money.ex:88 Decimal.round/3 에 사용자 입력 precision 전달 |
| 2 | P1 | P2 | web | GHSA-xxxx | lodash@4.17.20 → 4.17.21 | devDependency, scripts/build.js:12 에서만 require, 입력은 저장소 내 고정 파일 |
| 3 | P0 | P0 | api | CVE-yyyy (KEV) | ... | KEV 등재 — 도달성 무관 유지 |
```

좋은 사유: 위치 + 무엇이 어디로 흐르는지 / 왜 닿지 않는지. 나쁜 사유: "아마 안 씀", "오래된 CVE", "ID 가 이상함".
