<div align="center">

# security-sweep

**한 문장으로 여러 프로젝트 · 서버 · 컨테이너 이미지의 알려진 취약점을 한 번에 훑는 Claude Code 스킬**

[![CI](https://github.com/baryonlabs/security-sweep/actions/workflows/ci.yml/badge.svg)](https://github.com/baryonlabs/security-sweep/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/baryonlabs/security-sweep?sort=semver)](https://github.com/baryonlabs/security-sweep/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Ecosystems](https://img.shields.io/badge/ecosystems-npm%20%C2%B7%20PyPI%20%C2%B7%20Hex%20%C2%B7%20Go%20%C2%B7%20Cargo%20%C2%B7%20Composer%20%C2%B7%20RubyGems%20%C2%B7%20Maven-555)
![Claude Code](https://img.shields.io/badge/Claude%20Code-plugin-D97757)

[빠른 시작](#빠른-시작) · [동작 방식](#동작-방식) · [우선순위](#우선순위) · [다른 도구와 비교](#다른-보안-도구와-무엇이-다른가) · [FAQ](#faq) · [English](#english)

**Website:** [baryonlabs.github.io/security-sweep](https://baryonlabs.github.io/security-sweep/)

</div>

```text
> /security-sweep:security-sweep ./work 전체 점검해줘

● 도구 확인: osv-scanner ✓ trivy ✓ govulncheck ✗ (Go는 grep으로 추정)
● 탐색: 프로젝트 6개 (npm · PyPI · Hex · Go · Cargo + 비밀값 샘플)
● 스캔 → OSV 검증 → 도달성 → 보고서
● 자동 판정:   P0 1 · P1 11 · P2 9 · P3 2
● 코드 확인 후: P0 0 · P1 6 · P2 15 · P3 2   (조정 12건, 사유는 triage.md)
    - go-app  GO-2021-0113  P0→P1  language.Parse 인자가 상수라 외부 입력이 닿지 않음
    - py-app  pyyaml 5.3    P1→P2  safe_load만 사용, 취약한 full_load 미사용
    - rust-app smallvec     P1→P2  취약 함수 insert_many 미사용
● 수정 명령 제안 (실행하지 않음): npm audit fix · mix deps.update sweet_xml · cargo update -p smallvec …
```

<sub>위는 이 저장소의 `test/fixtures`를 새 Claude Code 세션에서 실제로 돌린 결과를 줄인 것입니다. 실제 개발 머신 26개 프로젝트 결과는 [예시 폴더](examples/dev-machine-2026-10-23)에 있습니다.</sub>

**osv-scanner와 trivy로 훑고 → 모든 CVE/GHSA ID를 OSV API로 실재 검증하고 → CISA KEV·EPSS로 보강하고 → 코드에서 실제로 쓰는지(도달성) 판정해 → P0~P3 우선순위 보고서를 만듭니다.** 기본은 읽기 전용이고, 서버에는 아무것도 설치하지 않습니다.

## 왜 만들었나

비슷한 도구는 이미 있습니다. 각자 잘하는 범위가 다릅니다:

- **secondsky 의 vulnerability-scanning 스킬** — 단일 저장소의 의존성·코드 스캔 절차를 잘 안내합니다.
- **Cornjebus/security-analyzer** — 한 코드베이스에 대한 심층 보안 분석(코드 리뷰 중심)입니다.
- **osv-mcp** — OSV 데이터베이스를 MCP 도구로 조회하게 해 줍니다. 조회 수단이지 스윕 워크플로는 아닙니다.
- **raptor** — 공격적 보안 리서치·퍼징·익스플로잇 검증 쪽 에이전트 프레임워크입니다.

그런데 "**내 체크아웃 디렉터리 수십 개 + 서버 몇 대 + 운영 이미지**를 한 번에 돌리고, 스캐너가 내놓은 ID 가 진짜인지 확인하고, 실제 코드에서 쓰는 것부터 보여 줘" 를 한 번에 하는 스킬은 찾지 못했습니다. 특히 LLM 은 CVE 번호 생김새만 보고 "가짜 같다"고 판단하는 실수를 합니다 — 예를 들어 `CVE-2026-97853` 은 이상해 보여도 OSV 에 실재하는 Elixir `decimal` DoS 취약점(`EEF-CVE-2026-97853`)이고, 반대로 그럴듯한 ID 가 404 일 수도 있습니다. 같은 레코드에 별칭으로 적힌 `GHSA-6c27-994x-c52f` 도 직접 조회하면 404 라서, 별칭까지 따로 확인합니다. 이 스킬은 **판단을 OSV 조회 결과에만** 근거하게 합니다.

## 다른 보안 도구와 무엇이 다른가

### 쉽게 말하면: 탐정과 공항 검색대

![탐정과 공항 검색대: 로직 결함은 AI 보안 리뷰가, 알려진 취약점은 스캐너 스윕이 찾습니다](docs/easy-compare.webp)

<sub>그림: ChatGPT 이미지 생성. 문구를 고치기 쉬운 [SVG 버전](docs/easy-compare.svg)도 있습니다.</sub>

| | **탐정** — AI 보안 리뷰<br/><sub>Codex Security · Claude Security · `/security-review`</sub> | **공항 검색대** — 스캐너 스윕<br/><sub>security-sweep · elixir-security-audit</sub> |
|---|---|---|
| 하는 일 | 코드를 처음부터 **읽고 추리**해서 "이 문은 잠겨 있지 않네" 같은 **설계·로직 결함**을 찾습니다 | 모든 가방(프로젝트·서버·이미지)을 통과시키며 **수배 목록(CVE DB)에 오른 위험물**을 빠짐없이 찾습니다 |
| 잘 찾는 것 | 인가 우회, 잘못된 신뢰 경계, 처음 보는 수법 | 오래된 라이브러리, 서버 OS 패키지 취약점, 흘린 비밀값, 언어별 위험 API |
| 놓치기 쉬운 것 | 수배 목록 대조 (의존성 CVE는 직접 안 봄) | 목록에 없는 새로운 수법 |
| 결과 | 똑똑하지만 돌릴 때마다 조금씩 다름 | 같은 입력이면 **항상 같은 결과** |
| 확인 방법 | 다른 에이전트가 한 번 더 검증 | 수배 목록이 **진짜인지 OSV로 조회**하고, 그 물건을 **실제로 꺼내 쓰는지(도달성)** 확인 |
| 비용 | 모델 토큰 (스캔마다) | 스캐너는 무료, LLM은 분류할 때만 |

**그래서 둘 다 씁니다.** 검색대로 알려진 위험을 먼저 전부 걸러내고, 중요한 저장소는 탐정에게 맡겨 숨은 로직 결함을 찾습니다.

| 이럴 때 | 이것부터 |
|---|---|
| "우리 프로젝트·서버 전체에 알려진 취약점 있나?" | **security-sweep** |
| "이 Phoenix 앱 고쳐 줘" | **elixir-security-audit** |
| "PR 하나 머지 전에 빨리 봐 줘" | `/security-review` |
| "결제·인증 같은 핵심 저장소를 깊게 털어 줘" | **Claude Security** 또는 **Codex Security** |


### 자세히 비교

![보안 점검 도구 비교: Codex Security, /security-review, Claude Security, elixir-security-audit, security-sweep](docs/comparison.svg)

| | OpenAI **Codex Security** | Claude Code **`/security-review`** | Anthropic **Claude Security** 플러그인 | **elixir-security-audit** | **security-sweep** |
|---|---|---|---|---|---|
| 접근 방식 | LLM이 코드를 읽고 탐지 (CLI·SDK·Codex 플러그인·GitHub Action) | LLM 1회 보안 패스 | LLM 멀티에이전트 (아키텍처 → 위협 모델 → 탐색 → 독립 검증) | 결정적 스캐너 + LLM 분류·수정 | 결정적 스캐너 + LLM 분류 |
| 범위 | 저장소·경로·diff, deep 모드, 여러 저장소 bulk 스캔 | 현재 브랜치 | 저장소 전체·일부, 브랜치·PR·커밋 diff | Elixir/Phoenix 프로젝트 1개 | 디렉터리 아래 모든 프로젝트 + 서버 + 컨테이너 이미지 |
| 의존성 CVE | 직접 스캔하지 않음 (Snyk·Endor 결과 가져오기) | 다루지 않음 | 다루지 않음 (공식 문서: 기존 의존성 스캐너와 병행 권장) | mix_audit · hex.audit · OSV | OSV-Scanner (전 생태계) |
| CVE 실재 검증 | — | — | — | OSV 대조 | OSV 조회 + CISA KEV + EPSS |
| 수정 | `cs patch`, `verify-fix` | 보고 중심 | `patches/`에 패치 파일, 자동 적용 안 함 | 별도 브랜치에 커밋 (승인 후) | 읽기 전용, 언어별 스킬로 넘김 |
| LLM 없이 실행 | 불가 | 불가 | 불가 | `scan.sh` 단독 가능 | 스크립트 단독·`--offline` 가능 |
| 필요 조건 | OpenAI 로그인·API 키 (Bedrock 등 가능), Node 22+ | Claude Code | 유료 플랜·API, python3 3.9+ | Claude Code, Elixir | Claude Code, osv-scanner, trivy |

**대체가 아니라 조합입니다.** 세 LLM 도구는 사람 보안 연구자처럼 코드를 읽어 **로직 결함**(인가 우회, 잘못된 신뢰 경계 등)을 찾는 데 강합니다. 이 저장소의 스킬은 **알려진 취약점**(의존성 CVE, 언어별 위험 API, 서버 OS 패키지)을 결정적 스캐너로 빠짐없이 훑고, CVE가 실재하는지와 코드에서 실제로 쓰는지를 확인합니다. Claude Security 공식 문서도 "기존 정적 분석·의존성 스캐너와 함께 쓰라"고 안내합니다.

권장 순서: `security-sweep`로 전체를 훑기 → Elixir 프로젝트는 `elixir-security-audit`로 수정 → 중요한 저장소는 Claude Security 또는 Codex Security로 로직 결함 딥스캔.

<sub>출처: [openai/codex-security](https://github.com/openai/codex-security) README·[agent workflows](https://github.com/openai/codex-security/blob/main/docs/agent-workflows.md), [Claude Security 문서](https://code.claude.com/docs/en/claude-security), [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review). 2026-10-23 기준이며 각 도구는 계속 바뀝니다.</sub>

## 빠른 시작

```text
/plugin marketplace add baryonlabs/security-sweep
/plugin install security-sweep@baryonlabs-security
```

같은 마켓플레이스에 Elixir 전용 점검·수정 스킬도 있습니다: `/plugin install elixir-security-audit@baryonlabs-security`

또는 스킬만 복사:

```bash
git clone https://github.com/baryonlabs/security-sweep
cp -r security-sweep/skills/security-sweep ~/.claude/skills/
```

### 원샷 프롬프트

플러그인으로 설치했다면 명령은 `/security-sweep:security-sweep`입니다(스킬 폴더만 복사했다면 `/security-sweep`).

```text
/security-sweep:security-sweep ~/work 아래 모든 프로젝트 취약점 점검해줘
/security-sweep:security-sweep 서버 deploy@web1, deploy@web2 점검. 설치는 하지 말고 보고서만
/security-sweep:security-sweep 이미지 myapp:prod 랑 실행 중인 컨테이너 전부 CVE 확인
/security-sweep:security-sweep CVE-2026-97853 이 우리 프로젝트에 영향 있는지 확인해줘
```

더 많은 예시: [`references/prompts.md`](skills/security-sweep/references/prompts.md)

### 실제 예시

![한 번 돌리고, 고치고, 다시 확인: 5건 → 1건](docs/before-after.webp)

개발 머신 한 대(프로젝트 26개)를 한 번 돌리고 → 한 프로젝트를 코드로 검토하고 → 패치한 뒤 → 그 프로젝트만 다시 스캔해 5건이 1건으로 줄어드는 과정을, 가명 처리한 실제 보고서와 함께 정리했습니다: [`examples/dev-machine-2026-10-23`](examples/dev-machine-2026-10-23)

## 동작 방식

![한 문장으로 전체 보안 스윕: 탐색 → 스캔 → 검증 → 도달성 → 보고서](docs/sweep-pipeline.webp)

```mermaid
flowchart LR
  R[한 문장 요청<br/>루트 · 서버 · 이미지] --> D[discover.sh<br/>lockfile로 프로젝트 판별]
  subgraph SW[sweep.sh · 읽기 전용]
    O[osv-scanner] & T[trivy fs · image · rootfs] & G[govulncheck] & E[elixir-security-audit]
  end
  D --> SW
  SW --> V[verify_cves.py<br/>OSV 실재 · KEV · EPSS]
  V --> RE[reachability.py<br/>called · imported · not-imported]
  RE --> RP[report.py<br/>P0~P3 · MD · HTML]
  RP --> C[Claude 분류<br/>코드 근거로 확정·조정]
```

스킬이 하는 일:

0. **도구 확인** — osv-scanner, trivy, (선택) govulncheck, elixir-security-audit. 없으면 설치 명령을 보여 주고 묻습니다.
1. **탐색** — 루트 아래 lockfile 로 프로젝트·생태계 판별 → `targets.json`
2. **스캔** — 프로젝트별 osv-scanner, trivy fs(비밀·설정), 이미지 trivy, 서버 ssh(읽기 전용)
3. **검증** — 모든 ID 를 OSV 에 조회, KEV·EPSS 보강
4. **도달성** — govulncheck / 취약 심볼 grep / import grep
5. **보고서** — `findings.json`, `REPORT.md`, `REPORT.html`
6. **Claude 분류** — P0/P1 마다 코드 근거를 직접 열어 확정·조정(한 줄 사유) → 요약, 상위 항목, 프로젝트별 다음 명령
7. **선택** — 보고서 공유, 주간 재실행 예약

스윕은 **아무것도 고치지 않습니다.** 끝나면 프로젝트별로 수정을 제안만 합니다 (Elixir 는 elixir-security-audit 로 인계, 그 외는 브랜치 + 최소 업그레이드).

## 스크립트 단독 사용

Claude 없이 파이프라인만 돌릴 수 있습니다 (bash + python3 표준 라이브러리):

```bash
S=skills/security-sweep/scripts
OUT=./security-sweep-$(date +%Y%m%d-%H%M)

bash    $S/discover.sh ~/work --max-depth 4 --out "$OUT"
bash    $S/sweep.sh --targets "$OUT/targets.json" \
          --server deploy@web1 --image myapp:prod --out "$OUT"   # --no-secrets 선택
python3 $S/verify_cves.py "$OUT"                                  # --offline, --cache DIR
python3 $S/reachability.py "$OUT"
python3 $S/report.py "$OUT"
open "$OUT/REPORT.html"
```


## 활용법 (CI & 정기 운영)

보안은 한 번 검사하고 끝나는 것이 아니라, **"코드가 추가될 때 막고(CI)"**, **"새 제로데이가 발표될 때 발견하는(정기 운영)"** 지속적인 루틴이 핵심입니다.

### 1. CI 게이트 (PR 머지 차단)
의존성 파일(`package-lock.json`, `poetry.lock`, `requirements.txt`, `mix.lock` 등)이 변경된 PR에서 신규 **P0(KEV 실전 악용 취약점)**이나 치명적인 비밀값이 발견되면 머지를 자동 차단합니다:

```bash
# 1) 변경된 프로젝트 스캔
bash skills/security-sweep/scripts/sweep.sh --targets targets.json --out ./out
python3 skills/security-sweep/scripts/verify_cves.py ./out --offline
python3 skills/security-sweep/scripts/report.py ./out

# 2) P0 취약점 유입 시 빌드 실패 (종료 코드 1)
python3 -c "import json, sys; s=json.load(open('./out/summary.json')); sys.exit(1 if s['counts']['P0'] > 0 else 0)"
```

### 2. 서버 무설치 정기 점검 (Zero-Install Weekly Cron)
외부 도구(Trivy 등) 설치가 금지된 폐쇄망 서버나 여러 사용자/학생이 공용으로 쓰는 GPU 서버도 안전하게 점검할 수 있습니다. 서버에서 코드를 실행하지 않고 정적 메타데이터(`.dist-info`)만 수집하여 로컬 분석 머신으로 가져옵니다:

```bash
# [원격 서버 실행] Python 인터프리터 실행 없이 메타데이터만 정적 수집 (심볼릭링크 차단)
python3 scripts/inventory.py collect --host 4090-gpu --venv /home/user/venv1 --output inventory.json

# [로컬 머신 실행] 가져온 인벤토리를 OSV API에 질의하여 취약점 판정
python3 scripts/inventory.py import inventory.json --out ./weekly-out
python3 scripts/report.py ./weekly-out
```

### 3. 주간 변경 추적 & 메신저 알림 (Discord / Slack)
단순한 취약점 건수만 비교하면 네트워크 장애로 인한 누락을 "해결"로 오인하기 쉽습니다. `operations.py`는 실제 점검 범위(`coverage.json`)와 결합하여 **신규 유입(`new`), 해결 확인(`resolved`), 미점검(`not_observed`)**을 정밀하게 구분합니다:

```bash
# 지난주 결과와 비교하여 diff.json 및 알림용 summary.json 생성
python3 scripts/operations.py ./this-week --previous ./last-week

# Discord / Slack 웹훅으로 P0/P1 변동 내역 전송
# 예: "🔔 [4090 주간 보안 점검] P0: 0건 · P1: 2건 (신규 1, 해결 2, 미관측 1)"
```

---

## 누구나 쉽게 보안을 유지하는 법 & 공식 보안 사이트

보안 사고의 90% 이상은 복잡한 해킹 기법이 아니라, **"이미 수개월 전 패치가 공개된 알려진 취약점(1-day CVE)"**을 방치해서 일어납니다. 아래의 3단계 루틴과 공식 보안 사이트들을 활용하면 개인 개발자나 소규모 팀도 기업 수준의 보안 체계를 유지할 수 있습니다.

### 💡 누구나 쉽게 실천하는 3단계 보안 루틴

1. **자동화된 정기 점검 (주 1회 월요일)**
   - 코드를 수정하지 않아도 매일 새로운 CVE가 취약점 DB에 등록됩니다.
   - `security-sweep` 주간 Cron을 걸어두고, 평소에는 메신저(Discord/Slack) 요약 알림만 확인합니다.
2. **우선순위 기반 패치 (P0 즉시 조치 → P1 계획 조치)**
   - 수백 개의 경고를 한 번에 다 고칠 수는 없습니다.
   - **P0 (CISA KEV 등재):** 지금 해커들이 실제로 공격 도구로 쓰고 있는 취약점이므로 즉시 라이브러리를 업데이트합니다.
   - **P1 (High/Critical 또는 EPSS ≥ 0.1):** 외부 서비스에 노출된 인터페이스와 연관된 패키지부터 순차적으로 업그레이드합니다.
3. **공식 정부·보안 기관의 보안 공지 정기 구독**
   - 아래 안내된 공식 정부 사이트(보호나라 등)의 주간 보안공지 및 긴급 보안 패치 알림을 확인합니다.

### 🏛️ 대한민국 정부 & 공공 보안 포털

취약점 확인, 최신 사이버 위협 동향 파악, 침해사고 발생 시 공식 신고 창구입니다:

| 기관 / 서비스 | 링크 | 주요 역할 및 활용법 |
|---|---|---|
| **KISA 보호나라 (KrCERT/CC)** | [boho.or.kr](https://www.boho.or.kr) | **한국인터넷진흥원 국가사이버위협 침해대응센터.** 주간 보안공지, 최신 취약점 권고문, 랜섬웨어 복구도구 및 침해사고 무료 신고 지원 |
| **KISA 취약점 신고·포상제 (Bug Bounty)** | [취약점 제보 포털](https://www.boho.or.kr/kr/subPage.do?menuNo=205020) | 소프트웨어/제품의 신규 보안 결함 발견 시 정부에 공식 제보하여 개발사 패치를 유도하고 포상금을 지원받는 공식 창구 |
| **국가사이버안보센터 (NCSC)** | [ncsc.go.kr](https://www.ncsc.go.kr) | **국가정보원 주관.** 국가 사이버위협 경보 단계(정상/관심/주의/경계/심각), 공공·IT 보안 가이드라인 및 주요 침해사고 분석 보고서 제공 |
| **경찰청 사이버범죄 신고시스템 (ECRM)** | [ecrm.police.go.kr](https://ecrm.police.go.kr) | 해킹 피해, 서버 침해, 악성코드 유포 등 사이버 범죄 피해 시 온라인 수사의뢰 및 정식 피해 접수 |
| **개인정보보호위원회 (PIPC)** | [pipc.go.kr](https://www.pipc.go.kr) | 개인정보 유출 사고 신고, 개인정보 안전성 확보조치 기술 기준(암호화, 접속기록 보관 등) 공식 안내 |

### 🌐 글로벌 공인 취약점 데이터베이스 & 연구 기관

`security-sweep`이 실시간으로 교차 검증하는 글로벌 표준 보안 리소스입니다:

| 데이터베이스 / 기관 | 링크 | 신뢰도 및 판정 기준 |
|---|---|---|
| **CISA KEV Catalog** | [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | **미국 사이버안보청(CISA) 공식 카탈로그.** 해커가 실제 공격에 사용 중임이 확인된 취약점 목록 (security-sweep **P0** 판정 기준) |
| **NIST NVD (National Vulnerability Database)** | [nvd.nist.gov](https://nvd.nist.gov) | **미국 국립표준기술연구소 공식 DB.** 모든 공인 CVE의 CVSS 점수, 공격 벡터(Network/Local), 영향도 공식 분석 |
| **OSV.dev (Open Source Vulnerabilities)** | [osv.dev](https://osv.dev) | **구글 및 OpenSSF 주도 오픈소스 통합 DB.** 정확한 커밋/버전 범위 검증 (security-sweep 실재 판정 기준) |
| **FIRST EPSS** | [first.org/epss](https://www.first.org/epss/) | **향후 30일 내 실제 악용될 확률(0~1)을 통계 모델로 예측.** EPSS ≥ 0.1(상위 10% 악용 가능성) 항목을 security-sweep **P1**으로 지정 |
| **CVE.org (CVE Program)** | [cve.org](https://www.cve.org) | **국제 표준 CVE 식별자 등록소 (MITRE 운영).** 공식 취약점 명명 및 공인 레코드 조회 |
| **GitHub Advisory Database** | [github.com/advisories](https://github.com/advisories) | npm, PyPI, Go, Maven, Cargo, Composer, NuGet, Hex 등 생태계별 상세 보안 권고 (GHSA) |

---

## 출력

```
security-sweep-YYYYMMDD-HHMM/
  coverage.json     대상별 점검 상태 (scanned / inventory-only / failed)
  manifest.json     실행 환경, 도구 버전 및 재현성 정보
  targets.json      탐색된 프로젝트 (경로, 생태계, lockfile)
  tools.txt         도구·서버별 실행 상태 (건너뜀 사유)
  raw/              osv/, trivy-fs/, elixir/, govulncheck/, image/, server/, inventory/
  verified.json     ID 별 OSV 실재 여부, 별칭, 심각도, 수정 버전, KEV, EPSS
  reach.json        called / imported / not-imported / unknown + 근거 file:line
  findings.json     정규화·우선순위가 매겨진 전체 항목
  summary.json      운영/알림 연동용 기계 판독형 요약
  diff.json         주간 비교 결과 (new, persistent, resolved, not_observed)
  REPORT.md         요약 → P0/P1 → 대상별 → OSV 미등재 → 다음 행동
  REPORT.html       같은 내용, 외부 리소스 없는 단일 파일 (다크모드)
  triage.md / .json Claude 조정 표 및 증거 해시 바인딩 재검토 파일
```

## 우선순위

| 우선순위 | 조건 |
|----------|------|
| **P0** | CISA KEV 등재, 또는 critical/high 이고 실제 호출(`called`) |
| **P1** | critical/high 이고 `imported`/`unknown`, 또는 EPSS ≥ 0.1, 또는 비밀 발견 |
| **P2** | medium, 또는 high 인데 `not-imported` |
| **P3** | low/unknown, 낮은 설정 문제 |
| 검증 실패 | OSV 404 — 우선순위 없이 별도 섹션 |

`not-imported` 는 "안전"이 아닙니다 — 전이 의존성은 직접 import 없이도 실행됩니다. 근거와 수동 확인 방법: [`references/prioritize.md`](skills/security-sweep/references/prioritize.md)

## 요구 사항

- bash, python3 (표준 라이브러리만)
- [`osv-scanner`](https://github.com/google/osv-scanner) 와 [`trivy`](https://github.com/aquasecurity/trivy) 중 하나 이상 (둘 다 권장) — macOS `brew install osv-scanner trivy`
- 선택: [`govulncheck`](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) (Go 호출 그래프 도달성), [`elixir-security-audit`](https://github.com/baryonlabs/elixir-security-audit) (Hex 프로젝트)
- 서버: ssh 키 인증. 원격 trivy 는 선택 (없으면 패키지 목록만 수집) — [`references/servers.md`](skills/security-sweep/references/servers.md)
- 네트워크: api.osv.dev, cisa.gov(KEV), api.first.org(EPSS). 없으면 `--offline` (검증 칸 미검증)

## 안심하고 실행할 수 있는 이유 (정보 탈취 0% & 셀프 검증)

보안 진단 도구 자체가 백도어가 되거나 사용자의 소중한 코드와 비밀값을 외부로 빼돌려서는 절대 안 됩니다. `security-sweep`은 **Zero Telemetry(원격 수집 없음)**와 **100% 투명성**을 원칙으로 하며, 사용자가 직접 코드를 검증할 수 있습니다.

### 🛡️ 정보 보호 4대 약속
1. **외부 유출 0% (No Phone-Home):** 사용자 코드, 저장소 경로, 파일 내용, 호스트 정보를 수집하거나 외부 분석 서버(Analytics/Telemetry)로 전송하는 코드가 **단 1줄도 없습니다.**
2. **공식 취약점 DB 3곳만 질의:** 외부 네트워크 통신은 오직 공식 취약점 조회(Google OSV `api.osv.dev`, CISA KEV `cisa.gov`, FIRST EPSS `api.first.org`)를 위한 공개 CVE 식별자 조회(GET)에만 사용됩니다.
3. **100% 오프라인 지원 (`--offline`):** 인터넷 통신이 일체 차단된 보안 폐쇄망이나 에어갭 환경에서도 로컬 캐시와 lockfile만으로 완벽하게 동작합니다.
4. **비밀값 원문 자동 마스킹 (`mask_secrets`):** 스캐너가 실수로 API 키나 프라이빗 키를 발견하더라도, 보고서와 산출물 디렉터리(`OUT/`)에는 위치와 종류만 남기고 원문은 안전하게 마스킹됩니다.

### 🔍 직접 확인하는 1초 셀프 검증 코드 (Self-Audit)
터미널에서 아래 명령을 직접 실행하여 외부 전송이나 추적 코드가 전혀 없음을 누구나 직접 검증할 수 있습니다:

```bash
# 1. 스크립트가 참조하는 모든 외부 도메인 전수 추출
grep -rhoE --exclude="*.pyc" "https?://[a-zA-Z0-9.-]+" skills/security-sweep/scripts/ | sort -u
# (확인 결과: api.osv.dev, cisa.gov, api.first.org 등 공인 취약점 DB 및 공식 안내 외 외부 URL 전무)

# 2. 텔레메트리 / 트래커 / 외부 데이터 수집 코드 부재 검사
grep -rnE --exclude="*.pyc" "(telemetry|analytics|track|phone_home)" skills/security-sweep/scripts/
# (출력 결과: 0건 — 백그라운드 정보 수집 코드가 전혀 없습니다)

# 3. 비밀키 원문 유출 방지 및 마스킹 안전장치 테스트
bash test/run.sh
# (통합 테스트에서 더미 비밀키 SWEEPFAKEJUNKBODY와 PEM 헤더가 결과물에 전혀 남지 않음을 자동 검증)
```

---

## 만든 사람 & 오픈소스 피드백 환영

`security-sweep`은 **연세대학교 글로벌인재대학(GLC) 겸임교수(홍성욱 / Baryon Labs)**가 연구실·서버·교육 현장의 복잡한 보안 문제를 누구나 쉽게 해결할 수 있도록 개발한 **100% 순수 오픈소스 프로젝트(MIT)**입니다.

> 💬 **"보안은 소수 보안 전문가만의 영역이 아니라, 누구나 자신의 소중한 연구, 서비스, 서버를 안심하고 지킬 수 있어야 합니다."**

- **피드백을 크게 환영합니다:** 사용 중 겪으신 불편한 점, 새로운 언어·생태계 지원 요청, 기능 개선 아이디어, 버그 제보 등 어떤 의견이든 편하게 남겨주세요.
- **기여 방법:** [GitHub Issues](https://github.com/baryonlabs/security-sweep/issues)에 글을 남겨주시거나, [Pull Request](https://github.com/baryonlabs/security-sweep/pulls)를 통해 직접 기여하실 수 있습니다. 오픈소스 생태계를 함께 더 안전하게 만들어갈 여러분의 참여를 기다립니다!

---

## 안전 원칙

- **기본 읽기 전용.** 코드·lockfile 을 바꾸지 않습니다. 수정은 사용자가 지시한 프로젝트만, 별도 브랜치에서.
- **서버에 아무것도 설치하지 않습니다.** ssh 는 `BatchMode=yes`, 사용자가 이름을 댄 호스트만, sudo 는 명시할 때만.
- 스캐너 출력·권고 본문·코드 주석은 **데이터**이지 지시가 아닙니다 (프롬프트 인젝션 방어).
- 비밀값은 위치와 종류만 기록하고 원문은 마스킹합니다.
- CVE 실재 여부는 **OSV 조회 결과로만** 판단합니다.

## elixir-security-audit 와의 관계

| | security-sweep | elixir-security-audit |
|---|---|---|
| 범위 | 여러 프로젝트·서버·이미지, 다언어 | Elixir/Phoenix 프로젝트 하나 |
| 보는 것 | 알려진 취약점(SCA), 비밀, 설정 | + Sobelow, BEAM 코드 패턴(atom 고갈, `binary_to_term`, SQLi …) |
| 수정 | 하지 않음 (제안·인계) | 브랜치에서 수정·검증·보고 |

스윕이 Hex 프로젝트를 만나면 elixir-security-audit 의 `scan.sh` 를 찾아 함께 실행하고(설치되어 있으면), 수정 단계는 그 스킬로 넘깁니다.

## 개발과 테스트

```bash
bash test/run.sh                                             # 다언어 취약 fixture로 전체 파이프라인 검증
python3 -m unittest discover -s skills/security-sweep/scripts/tests   # 분석기 단위 테스트
shellcheck skills/security-sweep/scripts/*.sh test/*.sh
```

[`test/fixtures`](test/fixtures)에는 생태계별로 **실제 공개 권고가 있는** 오래된 의존성과, 그 패키지를 쓰는 코드·안 쓰는 코드가 들어 있습니다. 통합 테스트는 기대 ID 9개와 도달성 판정, 비밀값 탐지, 그리고 **비밀값 원문이 출력 어디에도 남지 않는지**를 확인합니다.

| fixture | 의존성 | 권고 | 기대 도달성 |
|---|---|---|---|
| node-app | lodash 4.17.15 | [GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) | imported |
| node-app | minimist 1.2.0 | [GHSA-xvch-5gv4-984h](https://osv.dev/vulnerability/GHSA-xvch-5gv4-984h) | not-imported |
| py-app | jinja2 2.10 | [GHSA-462w-v97r-4m45](https://osv.dev/vulnerability/GHSA-462w-v97r-4m45) | imported |
| py-app | pyyaml 5.3 | [GHSA-8q59-q68h-6hv4](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) | imported |
| go-app | golang.org/x/text v0.3.5 | [GO-2021-0113](https://osv.dev/vulnerability/GO-2021-0113) | called (`language.Parse`) |
| rust-app | smallvec 1.6.0 | [RUSTSEC-2021-0003](https://osv.dev/vulnerability/RUSTSEC-2021-0003) | imported |
| elixir-app | sweet_xml 0.6.6 | [GHSA-qpmc-wprv-x746](https://osv.dev/vulnerability/GHSA-qpmc-wprv-x746) | imported |
| with-secret | 가짜 RSA 키 헤더 | trivy private-key | 원문 마스킹 확인 |

## FAQ

<details><summary><b>서버에 뭔가 설치되나요?</b></summary>

아니요. `ssh -o BatchMode=yes`로 사용자가 이름을 댄 호스트에만 접속하고, 원격에 trivy가 있으면 `trivy rootfs`를 읽기 전용으로 실행합니다. 이때 trivy는 원격 사용자의 캐시 디렉터리에 취약점 DB를 내려받습니다(디스크 수백 MB). trivy가 없으면 패키지 목록(`dpkg-query`/`rpm -qa`/`apk info`)만 수집합니다. sudo는 사용자가 명시할 때만 씁니다.

> v0.1.x 기준으로 서버 점검은 접속 실패 처리와 컨테이너 이미지(`trivy image`)까지만 테스트됐습니다. 실제 리눅스 서버에 대한 `trivy rootfs`·패키지 목록 수집은 아직 실서버 검증 전이니, 결과를 보고 이슈로 알려 주세요.
</details>

<details><summary><b><code>not-imported</code>면 안전한가요?</b></summary>

아닙니다. 전이 의존성은 직접 import 없이도 실행됩니다. `not-imported`는 우선순위를 한 단계 낮출 근거일 뿐이며, 판정 방법은 [`prioritize.md`](skills/security-sweep/references/prioritize.md)에 있습니다. 함수 단위 도달성은 Go(govulncheck)와, OSV 권고에 취약 심볼이 적힌 경우에만 판정합니다.
</details>

<details><summary><b>CVE 번호가 가짜처럼 보이는데요?</b></summary>

생김새로 판단하지 마세요. `CVE-2026-97853`은 이상해 보여도 OSV에 실재하고, 그럴듯한 번호가 404일 수도 있습니다. 이 스킬은 OSV 조회 결과만 근거로 쓰고, 404는 "검증 실패" 섹션으로 따로 분리합니다.
</details>

<details><summary><b>네트워크가 없는 CI에서도 되나요?</b></summary>

`verify_cves.py --offline`을 쓰면 osv-scanner 출력에 포함된 OSV 레코드와 캐시만 사용합니다. 이 경우 trivy만 보고한 ID는 "미검증"으로 남습니다.
</details>

<details><summary><b>고쳐 주지는 않나요?</b></summary>

스윕은 의도적으로 읽기 전용입니다. 끝나면 프로젝트별 수정 명령(`npm audit fix`, `mix deps.update pkg`, `go get pkg@fixed` …)을 제안하고, Elixir 프로젝트는 [elixir-security-audit](https://github.com/baryonlabs/elixir-security-audit)로 넘겨 브랜치에서 수정·검증합니다.
</details>

## 기여

이슈와 PR을 환영합니다. [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하고, 이 도구 자체의 취약점은 [SECURITY.md](SECURITY.md)의 절차로 비공개 신고해 주세요.

---

## English

`security-sweep` is a Claude Code plugin/skill that turns one sentence ("scan everything under ~/work plus servers web1, web2 and image myapp:prod") into a full known-vulnerability sweep:

1. **discover** projects by lockfile (npm, PyPI, Hex, Go, Cargo, Packagist, RubyGems, Maven),
2. **scan** with osv-scanner and trivy (fs secrets/misconfig, images, `trivy rootfs` over read-only `ssh -o BatchMode=yes`, package-list fallback when trivy is absent), plus optional govulncheck and elixir-security-audit,
3. **verify** every CVE/GHSA/OSV ID against the OSV API — never judging an ID by how it looks — and enrich with CISA KEV and EPSS,
4. **reachability**: called / imported / not-imported / unknown with `file:line` evidence,
5. **report**: `findings.json`, `REPORT.md`, self-contained `REPORT.html`, with P0–P3 priorities,
6. Claude then opens the code evidence for every P0/P1, confirms or adjusts with a one-line reason, and proposes (but does not perform) per-project fixes.

Install: `/plugin marketplace add baryonlabs/security-sweep`, then `/plugin install security-sweep@baryonlabs-security`. Read-only by default; nothing is ever installed on servers.

## License

[MIT](LICENSE) © 2026 Baryon Labs
