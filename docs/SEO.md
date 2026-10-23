# SEO / AEO / GEO / LLMO / NEO 작업 기록 — security-sweep 사이트

- 사이트: https://baryonlabs.github.io/security-sweep/ (GitHub Pages 프로젝트 페이지, `site/` → `.github/workflows/pages.yml`)
- 방법: fire-your-seo-agency 스킬 (진단 → 구현 → 측정). 정공법만, 화면과 메타·JSON-LD 일치, curl(JS 없이)로 검증
- 작업일: 2026-10-23 · 재측정 예정일: **2026-11-06** (14일 후)

## Phase 0 점수표

| 레인 | 이전 (사이트 없음) | 이후 | 근거 |
|---|---|---|---|
| SEO | ❌ | ✅ | 정적 HTML 6페이지 + 404, 본문 전부 JS 없이 노출, 제목 50–60자·설명 150–160자, canonical, sitemap.xml(hreflang 포함) |
| AEO | ❌ | ✅ | 질문 1개 = 페이지 1개 (4개 의도 랜딩), h1 = 질문, 첫 문단 40자 내외 직답, 표·기준일, 가시 FAQ + FAQPage LD |
| GEO | ❌ | ⚠️ | llms.txt·llms-full.txt, AI 크롤러 전부 Allow 정책 작성. 단 프로젝트 페이지라 robots.txt·llms.txt가 호스트 루트에 없음 (아래 "알려진 한계") |
| LLMO | ⚠️ | ✅ | GitHub README가 이미 강한 학습 표면. 사이트에서 이름 표기 `security-sweep`·`Baryon Labs` 통일, Organization `sameAs` GitHub 연결 |
| NEO (네이버) | ❌ | ⚠️ | 한국어 정본 페이지, 모바일 360px 가로 스크롤 없음, 라벨-값 표 구조. 서치어드바이저 등록은 사용자 계정 필요 |
| 콘텐츠 운영 | ❌ | ⚠️ | 의도 랜딩 4개로 시작. 블로그·피드 없음 (오픈소스 프로젝트 규모상 보류), 질문 백로그는 아래에 |

## 레인별 구현 내용

### SEO
- 페이지: `/`(ko), `/en/`, `/ko/scan-all-projects/`, `/ko/verify-cve/`, `/ko/priority/`, `/ko/vs-claude-security/`, `404.html`
- 페이지마다 고유 title·description, canonical, `og:*`, `twitter:card=summary_large_image`, `theme-color`
- OG 이미지 `og.jpg` 1200×630 (177 KB, LinkedIn 소스에서 상단 크롭 + 배경색 패딩). PNG는 804 KB라 JPEG 채택
- `/`와 `/en/` 사이 hreflang ko/en/x-default 상호 참조 (HTML과 sitemap 양쪽)
- 내부 링크는 전부 상대 경로 (`/security-sweep/` 하위 경로에서 동작). 404.html만 GitHub Pages가 임의 경로에서 서빙하므로 `/security-sweep/` 절대 경로
- 외부 요청 없음: 시스템 폰트, 단일 CSS, 이미지 WebP·SVG에 width/height 명시 + lazy

### AEO
- 의도 랜딩 4개: h1 = 질문, 첫 문단 직답, 근거 표, 기준일(2026-10-23) 명시
  - 여러 프로젝트의 알려진 취약점을 한 번에 점검하려면? → "상위 폴더 하나를 지정해 security-sweep으로 한 번에 훑으면 됩니다."
  - CVE 번호가 진짜인지 어떻게 확인하나요? → "번호 생김새가 아니라 OSV API 조회 결과(200/404)로 확인합니다." (2026-10-23 실측: CVE-2026-97853 → 200, CVE-2099-00001 → 404)
  - 취약점 우선순위 P0~P3는 어떻게 정하나요? → "KEV 등재·심각도·도달성·EPSS를 조합한 규칙으로 매깁니다."
  - Claude Security·Codex Security와 무엇이 다른가요? → "AI 리뷰는 로직 결함을, security-sweep은 알려진 취약점을 찾습니다."
- 모든 페이지에 화면에 보이는 FAQ + 글자 단위로 같은 FAQPage JSON-LD

### GEO
- `llms.txt`(안내서), `llms-full.txt`(핵심 사실 전문: 설치, 파이프라인, 우선순위 규칙, 실측 예시, 비교, 원칙)
- `robots.txt`: 검색·실시간 fetch·학습 크롤러 모두 Allow (오픈소스라 인용·학습 모두 원함), Sitemap 줄
- 1차 소스 신호: 예시 수치(26개 프로젝트, 고유 권고 75개 전부 OSV 실재 확인, P1 107건 중 99건이 패키지 2개, 5건 → 1건)를 기준일·출처 링크와 함께 문단 단위로 서술

### LLMO
- JSON-LD `@graph`: Organization(Baryon Labs, `sameAs` GitHub), SoftwareApplication(DeveloperApplication, macOS·Linux, price 0, v0.1.1), SoftwareSourceCode(codeRepository, Python·Shell, MIT), WebPage, BreadcrumbList(하위 페이지), FAQPage. 같은 엔티티는 모든 페이지에서 같은 `@id`
- LD의 description은 화면 첫 문단(직답)과 동일 문장
- README 상단에 Website 링크 1줄 추가 (GitHub ↔ 사이트 상호 연결)

### NEO (네이버)
- 한국어가 정본(`/`), 모바일 우선 레이아웃 (360px에서 모든 페이지 scrollWidth = 360 확인)
- 라벨-값 표 구조, 원출처(OSV, GitHub 예시 보고서) 링크 병기
- 사이트 소유 확인 메타는 사용자 계정 발급 후 추가 (아래)

## 남은 수동 작업 (사용자 계정 필요)

1. **Pages 활성화**: 저장소 Settings → Pages → Source: GitHub Actions, 이후 `site/**` push 또는 workflow_dispatch로 배포
2. **Google Search Console**: URL 접두어 속성 `https://baryonlabs.github.io/security-sweep/` 추가 → HTML 태그 방식 소유 확인 → 사이트맵 `https://baryonlabs.github.io/security-sweep/sitemap.xml` 제출
3. **Bing Webmaster Tools**: GSC에서 가져오기(원클릭) → 사이트맵 확인 → `site:baryonlabs.github.io/security-sweep` 색인 확인. ChatGPT 검색·Copilot이 Bing 색인을 쓰므로 필수
4. **네이버 서치어드바이저**: searchadvisor.naver.com에 사이트 등록 → HTML 태그 소유 확인 → 사이트맵 제출 → 주요 페이지 수집 요청
   - 발급받은 태그를 모든 페이지 `<head>`에 추가 (빌드 시 공통 head에 한 줄):
   - `<!-- <meta name="naver-site-verification" content="발급받은_값"> -->`
5. Google·Bing·네이버 소유 확인 메타는 위 2~4에서 받은 값으로 추가한 뒤 재배포

## 알려진 한계

- **robots.txt·llms.txt 위치**: 크롤러는 호스트 루트(`https://baryonlabs.github.io/robots.txt`)만 읽습니다. 프로젝트 페이지의 `/security-sweep/robots.txt`는 정책 문서일 뿐 효력이 없습니다. `baryonlabs/baryonlabs.github.io` 저장소가 없으면 루트 robots.txt는 404 → 전부 크롤링 허용이므로 지금도 문제는 없지만, 명시 정책이 필요하면 그 저장소에 같은 robots.txt(Sitemap 줄 포함)와 llms.txt를 두세요. 사이트맵은 GSC·Bing·네이버에 직접 제출하면 됩니다
- `site/SEO.md`도 Pages 아티팩트에 포함되어 공개됩니다 (비밀 없음)
- 이미지 안 글자는 한국어라 `/en/`에서는 alt에 "(Korean labels)"로 표기
- IndexNow: 정적 Pages라 키 파일·핑 파이프라인 미구성 (Bing·네이버 등록 후 필요하면 추가)

## 측정 계획

**기준선 (2026-10-23)**: 사이트 없음 → 노출 0 · 클릭 0 · 색인 0 · AI 인용 0/8 (아래 질문)

**재측정 2026-11-06 (14일 후, 최근 2~3일 제외하고 비교)**:

| 지표 | 어디서 | 기록 |
|---|---|---|
| 색인 페이지 수 | GSC 페이지 보고서, `site:baryonlabs.github.io/security-sweep` (Google·Bing) | 6페이지 중 몇 개 |
| 노출·클릭·CTR·평균 순위 | GSC 실적, 네이버 서치어드바이저 콘텐츠 노출/클릭 | 페이지별 |
| AI 인용 | 아래 8개 질문을 Perplexity·ChatGPT(검색)·Google AI Overviews·네이버 AI 브리핑에 입력, 출처에 사이트·GitHub 노출 여부 O/X | 0/8 → ? |
| LLMO | 브라우징 끈 ChatGPT·Claude·Gemini에 "security-sweep Claude Code 스킬이 뭐야?" | 모름/틀림/맞음 (분기마다) |

AI 인용 측정 질문:
1. 여러 프로젝트 취약점 한 번에 점검하는 Claude Code 스킬
2. CVE 번호가 진짜인지 확인하는 방법
3. CVE-2026-97853
4. osv-scanner trivy 여러 저장소 한 번에
5. Claude Security와 의존성 스캐너 차이
6. 취약점 우선순위 KEV EPSS 도달성
7. scan all projects for known vulnerabilities Claude Code
8. Codex Security vs dependency scanner

판단: 노출이 먼저 움직입니다. 노출만 늘고 CTR이 낮으면 title·description을, 색인이 안 되면 GSC URL 검사·수집 요청을, AI 인용이 0이면 직답 문단·llms.txt·Bing 색인 순으로 점검합니다.

## 다음 질문 백로그 (전용 페이지 후보)

- 서버 취약점을 설치 없이 점검하려면? (servers.md 기반)
- 컨테이너 이미지 CVE를 한 번에 확인하려면?
- not-imported 취약점은 무시해도 되나요?
- 네트워크 없는 CI에서 취약점 점검하려면? (`--offline`)
- 검색어 데이터(GSC·서치어드바이저)가 쌓이면 상위 검색어 중 전용 페이지가 없는 질문을 우선 추가
