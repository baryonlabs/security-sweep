# 보안 스윕 보고서

- 생성: 2026-10-23 20:39
- 출력 디렉터리: `/home/dev/security-sweep-20261023-2025`
- 대상: 프로젝트 26, 서버 0, 이미지 0
- OSV 검증: 확인 75 / 404 0 / 미확인 0, KEV: cisa, EPSS: first.org

## 요약

| 우선순위 | 건수 | 기준 |
|---|---:|---|
| P0 | 0 | KEV 등재 또는 critical/high + 실제 호출 |
| P1 | 107 | critical/high + import·불명, EPSS ≥ 0.1, 비밀값 |
| P2 | 72 | medium, 또는 high 인데 직접 import 없음 |
| P3 | 2 | low / unknown |
| 검증 실패(OSV 404) | 0 | 우선순위 산정 제외 |

> 도달성 `not-imported` 는 직접 import 를 못 찾았다는 뜻일 뿐이다. 전이 의존성으로 쓰일 수 있으므로 안전을 의미하지 않는다.

## 도구 상태

| 도구 | 상태 | 비고 |
|---|---|---|
| osv-scanner | available | osv-scanner version: 2.7.0 |
| trivy | available | Version: 0.76.1 |
| govulncheck | missing | install: go install golang.org/x/vuln/cmd/govulncheck@latest |
| elixir-security-audit | available | (설치됨) |
| osv-scanner | skipped | mobile-app-a-android: no lockfile (manifest only) |
| osv-scanner | skipped | mobile-app-a-android-app: no lockfile (manifest only) |
| trivy | ok | mobile-app-a-android-app: fs secret,misconfig |
| trivy | ok | mobile-app-a-android: fs secret,misconfig |
| osv-scanner | ok | phoenix-saas-assets: exit 0 (no vulns) |
| trivy | ok | phoenix-saas-assets: fs secret,misconfig |
| osv-scanner | ok | phoenix-saas: exit 1 (vulns found) |
| trivy | ok | phoenix-saas: fs secret,misconfig |
| osv-scanner | ok | py-tool-a: exit 1 (vulns found) |
| osv-scanner | ok | mobile-app-a-server: exit 1 (vulns found) |
| trivy | ok | mobile-app-a-server: fs secret,misconfig |
| osv-scanner | skipped | py-tool-b: no lockfile (manifest only) |
| trivy | ok | py-tool-b: fs secret,misconfig |
| trivy | ok | py-tool-a: fs secret,misconfig |
| osv-scanner | ok | py-tool-c: exit 1 (vulns found) |
| trivy | ok | py-tool-c: fs secret,misconfig |
| osv-scanner | ok | desktop-app: exit 1 (vulns found) |
| osv-scanner | ok | workflow-engine: exit 1 (vulns found) |
| trivy | ok | desktop-app: fs secret,misconfig |
| osv-scanner | ok | workflow-engine-tools-inspect: exit 0 (no vulns) |
| trivy | ok | workflow-engine-tools-inspect: fs secret,misconfig |
| govulncheck | skipped | workflow-engine-tools-inspect: govulncheck not installed |
| osv-scanner | ok | workflow-engine-tools-trainer: exit 1 (vulns found) |
| trivy | ok | workflow-engine-tools-trainer: fs secret,misconfig |
| trivy | ok | workflow-engine: fs secret,misconfig |
| osv-scanner | skipped | mobile-app-b-android: no lockfile (manifest only) |
| trivy | ok | mobile-app-b-android: fs secret,misconfig |
| osv-scanner | ok | wp-publisher: exit 1 (vulns found) |
| osv-scanner | skipped | mobile-app-b-android-app: no lockfile (manifest only) |
| trivy | ok | mobile-app-b-android-app: fs secret,misconfig |
| osv-scanner | ok | desktop-app-packaging-windows: exit 1 (vulns found) |
| osv-scanner | ok | mobile-app-b-backend: exit 0 (no vulns) |
| trivy | ok | wp-publisher: fs secret,misconfig |
| trivy | ok | desktop-app-packaging-windows: fs secret,misconfig |
| trivy | ok | mobile-app-b-backend: fs secret,misconfig |
| osv-scanner | skipped | course-slides-midterm-example-android: no lockfile (manifest only) |
| osv-scanner | ok | course-slides-midterm-deck: exit 1 (vulns found) |
| trivy | ok | course-slides-midterm-example-android: fs secret,misconfig |
| trivy | ok | course-slides-midterm-deck: fs secret,misconfig |
| osv-scanner | ok | course-slides-midterm-mock-server: exit 0 (no vulns) |
| osv-scanner | ok | course-slides-midterm-deck-simple: exit 1 (vulns found) |
| trivy | ok | course-slides-midterm-mock-server: fs secret,misconfig |
| trivy | ok | course-slides-midterm-deck-simple: fs secret,misconfig |
| osv-scanner | ok | course-slides-midterm-templates: exit 1 (vulns found) |
| osv-scanner | ok | course-slides-w05-deck: exit 1 (vulns found) |
| trivy | ok | course-slides-midterm-templates: fs secret,misconfig |
| trivy | ok | course-slides-w05-deck: fs secret,misconfig |
| osv-scanner | skipped | course-slides-w07-release-src: no lockfile (manifest only) |
| trivy | ok | course-slides-w07-release-src: fs secret,misconfig |
| osv-scanner | ok | course-slides-w06-deck: exit 1 (vulns found) |
| osv-scanner | ok | course-slides-w07-deck: exit 1 (vulns found) |
| trivy | ok | course-slides-w06-deck: fs secret,misconfig |
| trivy | ok | course-slides-w07-deck: fs secret,misconfig |

## P0 / P1

| 우선순위 | 대상 | 패키지/종류 | ID | 심각도 | 근거 | 수정 버전 | 위치 |
|---|---|---|---|---|---|---|---|
| P1 | desktop-app | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app-packaging-windows | bottle@0.9.8 | PYSEC-2014-77 (CVE-2014-3137) | critical | 도달성 unknown | 0.10.12 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | bottle@0.9.8 | PYSEC-2022-227 (CVE-2022-31799) | critical | 도달성 unknown | 0.12.20 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 도달성 unknown | 2026.10.19 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | workflow-engine | 비밀값 | github-oauth | critical | 비밀값 노출 |  | build/dir5/dir6/file7.sh:5359 |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 도달성 imported | 13.0.0 | uv.lock |
| P1 | course-slides-midterm-deck | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-midterm-deck | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-midterm-deck | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | course-slides-midterm-deck-simple | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-midterm-deck-simple | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-midterm-deck-simple | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | course-slides-midterm-templates | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-midterm-templates | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-midterm-templates | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | course-slides-w05-deck | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-w05-deck | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-w05-deck | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | course-slides-w06-deck | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-w06-deck | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-w06-deck | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | course-slides-w07-deck | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 도달성 imported | 0.35.0 | package-lock.json |
| P1 | course-slides-w07-deck | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 도달성 imported | 0.35.4 | package-lock.json |
| P1 | course-slides-w07-deck | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 도달성 imported | 0.35.5 | package-lock.json |
| P1 | desktop-app | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | desktop-app-packaging-windows | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 도달성 unknown | 13.0.0 | requirements-win.txt |
| P1 | phoenix-saas | 코드 패턴 | EXS-CFG-001 | high |  |  | config/config.exs:36 |
| P1 | phoenix-saas | bandit@1.12.5 | EEF-CVE-2026-105659 (CVE-2026-105659) | high | 도달성 imported | 1.13.0 | mix.lock, mix.lock:2 |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | wp-publisher | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 도달성 imported | 13.0.0 | uv.lock |
| P1 | workflow-engine | 비밀값 | jwt-token | medium | 비밀값 노출 |  | build/dir5/auth.json:5 |
| P1 | workflow-engine | 비밀값 | jwt-token | medium | 비밀값 노출 |  | build/dir5/auth.json:6 |

<details><summary>도달성 근거</summary>

- **GHSA-332p-7hrc-92wf** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-8g5g-8vmr-9782** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-v9pv-5gc8-w2m6** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-w889-685w-c8fh** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-332p-7hrc-92wf** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-8g5g-8vmr-9782** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-v9pv-5gc8-w2m6** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-w889-685w-c8fh** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-midterm-deck)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-midterm-deck)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-midterm-deck)
  - `file17.js:30`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-midterm-deck-simple)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-midterm-deck-simple)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-midterm-deck-simple)
  - `file17.js:30`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-midterm-templates)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-midterm-templates)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-midterm-templates)
  - `file17.js:30`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-w05-deck)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-w05-deck)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-w05-deck)
  - `file17.js:30`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-w06-deck)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-w06-deck)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-w06-deck)
  - `file17.js:30`
- **GHSA-f88m-g3jw-g9cj** sharp (course-slides-w07-deck)
  - `file17.js:30`
- **GHSA-rgj7-g3m4-5g8c** sharp (course-slides-w07-deck)
  - `file17.js:30`
- **GHSA-wq5f-xc86-pv6w** sharp (course-slides-w07-deck)
  - `file17.js:30`
- **GHSA-22hg-r758-rrw9** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-27h8-gf7j-v5hc** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-3j72-p6qg-6xp7** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-58r4-6rv3-gfh8** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-5xm2-6676-qcp9** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-65qm-jvmh-6pqg** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-78g4-xqwv-q3g8** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-7mwm-ghpf-9vrm** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-9v9v-9qvf-h2hj** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-c6hw-5grf-ff96** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-cp9v-662q-vvx9** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-f2g6-542v-9j58** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-g4qv-2jxx-769h** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-g7cr-3p24-7wf7** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-g842-9rc4-69pw** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-gg2r-wvfm-q9rx** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-j4m9-6w36-pw47** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-jg86-v3jv-hrpm** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-mrfp-p49p-3hf2** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-p4wg-p73j-c528** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-pchr-8j38-3x4p** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-q45j-58j2-45rg** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **GHSA-xvh5-g6gv-559v** pillow (desktop-app)
  - `packaging/file18.py:7`
  - `src/dir19/file20.py:74`
  - `src/dir19/file21.py:189`
  - `src/dir19/file22.py:20`
  - `src/dir19/file23.py:121`
- **EEF-CVE-2026-105659** bandit (phoenix-saas)
  - `config/config.exs:30`
  - `config/runtime.exs:125`
- **GHSA-22hg-r758-rrw9** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-27h8-gf7j-v5hc** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-3j72-p6qg-6xp7** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-58r4-6rv3-gfh8** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-5xm2-6676-qcp9** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-65qm-jvmh-6pqg** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-78g4-xqwv-q3g8** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-7mwm-ghpf-9vrm** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-9v9v-9qvf-h2hj** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-c6hw-5grf-ff96** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-cp9v-662q-vvx9** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-f2g6-542v-9j58** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-g4qv-2jxx-769h** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-g7cr-3p24-7wf7** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-g842-9rc4-69pw** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-gg2r-wvfm-q9rx** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-j4m9-6w36-pw47** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-jg86-v3jv-hrpm** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-mrfp-p49p-3hf2** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-p4wg-p73j-c528** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-pchr-8j38-3x4p** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-q45j-58j2-45rg** pillow (wp-publisher)
  - `dir26/file27.py:188`
- **GHSA-xvh5-g6gv-559v** pillow (wp-publisher)
  - `dir26/file27.py:188`

</details>

## 대상별 결과

### 프로젝트: course-slides-midterm-deck

`/home/dev/projects/course-slides/midterm/deck`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: course-slides-midterm-deck-simple

`/home/dev/projects/course-slides/midterm/deck-simple`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: course-slides-midterm-templates

`/home/dev/projects/course-slides/midterm/templates`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: course-slides-w05-deck

`/home/dev/projects/course-slides/w05/deck`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: course-slides-w06-deck

`/home/dev/projects/course-slides/w06/deck`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: course-slides-w07-deck

`/home/dev/projects/course-slides/w07/deck`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-f88m-g3jw-g9cj (CVE-2026-114113) | high | 확인 | imported |  | 0.001 | 0.35.0 | osv-scanner | package-lock.json | sharp inherited vulnerabilities in libvips: CVE-2026-33327, CVE-2026-33328, CVE-2026-35590, CVE-2026-35591 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-rgj7-g3m4-5g8c (CVE-2026-114112) | high | 확인 | imported |  | 0.002 | 0.35.4 | osv-scanner | package-lock.json | sharp: Vulnerabilities in libheif: GHSA-g89c-p67h-r497 and GHSA-2jg2-4ch7-h545 |
| P1 | 취약 의존성 | sharp@0.34.5 | GHSA-wq5f-xc86-pv6w (CVE-2026-114111) | high | 확인 | imported |  | 0.001 | 0.35.5 | osv-scanner | package-lock.json | sharp : Vulnerability in librsvg dependency CVE-2026-96889 |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-5p2g-fcmc-qvqq (CVE-2025-71329) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: JXL and HEIF parsers allow denial of service through infinite loops |
| P2 | 취약 의존성 | image-size@1.2.1 | GHSA-w3rx-r6r6-pgpr (CVE-2025-71330) | high | 확인 | not-imported |  | 0.004 | 2.0.3 | osv-scanner | package-lock.json | image-size: ICNS parser allows denial of service through an infinite loop |

### 프로젝트: desktop-app

`/home/dev/projects/desktop-app`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 확인 | imported |  | 0.005 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow in ImagingJpegDecode |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 확인 | imported |  | 0.006 | 13.0.0 | osv-scanner | uv.lock | Pillow multi-frame loaders can reuse stale native image storage after mode transitions |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Argument Injection in Ghostscript call, potentially leading into RCE |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Infinite loop in MIC n_frames when the embedded TIFF |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: NULL dereference in ImagingExpand via rank filters on zero-size images |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TarIO negative size field causes infinite CPU-spin loop |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Out-of-bounds access in _imagingmorph on a zero-width image |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: APNG background disposal allocates full canvas before decompression bomb check |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: GIF seek keeps rejected size after DecompressionBombError, allowing DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock | Pillow: Bundled libopenjp2 2.5.4 in all wheels since 11.1.0 carries OSV-2025-219 heap-buffer-overflow write reachable fr |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Double free in ImagingScaleAffine on calloc failure via Image.transform |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap over-read in WMF/EMF rendering via 16-bit dimension truncation (Windows builds) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: OOB read in TiffDecode.c tile and RGBA paths leaks heap memory into pixels |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: NULL pointer dereference in Image.merge via an unvalidated band 0 |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Infinite loop in PdfParser.rewrite_pages on page tree Parent cycle |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: PNG eXIf chunk makes EXIF parsing run in quadratic time |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow writing JPEG comment after ICC profile fills buffer |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Decompression bomb check bypass in SpiderImagePlugin.seek() leads to unbounded allocation DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: MSP RLE decoder expands a tiny file into unbounded memory |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Invalid free in FreeType glyph rendering when a stroker is active |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic-time DoS in PDF save_all (PdfParser.next_object_id) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow PDF append accepts malformed shared page-tree DAG causing resource exhaustion |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Unbounded recursion parsing a PDF page tree or trailer chain (incomplete fix for CVE-2026-42310) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TIFF encoder ColorMap plane-size mismatch causes a heap out-of-bounds read |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TiffDecode returns uninitialized memory as pixels for short JPEG strips |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock |  Pillow: Memory disclosure and segfault in libtiff encoder via crafted TIFF tags |
| P2 | 취약 의존성 | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 확인 | not-imported |  |  | 2026.10.19 | osv-scanner | uv.lock | certifi bundles emSign root CAs with compromised intermediate CA keys |
| P2 | 취약 의존성 | opentelemetry-api@1.45.0 | GHSA-xcq7-p3pf-p88h (CVE-2026-114603) | medium | 확인 | not-imported |  |  | 1.45.1 | osv-scanner | uv.lock | OpenTelemetry Python: Unbounded tracestate parsing in opentelemetry-api |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-24rc-8hj2-v98c (CVE-2026-96638) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: BMP RLE decoder memory-amplification DoS via unbounded delta escape / absolute mode |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-254f-3936-288h (CVE-2026-112391) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: PdfParser can recurse without limit in get_value() and linearize_page_tree() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4558-3h8r-v8xp (CVE-2026-112394) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: P;2L and P;4L decoders may read 1 to 3 bytes past the passed buffer size |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-462x-pgg6-55fp (CVE-2026-112395) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow tiled-TIFF decoder reads past tile buffer in copy4 (Unpack.c:1290) |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rm8-3hmm-39fg (CVE-2026-96641) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Reachable undefined behavior in native integer operations, potentially leading to denial of service or logic int |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rr5-89j8-mwwm (CVE-2026-112396) | medium | 확인 | imported |  | 0.005 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap use-after-free when encoding TIFF to an in-memory buffer |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-74r2-7ff9-mjj2 (CVE-2026-112401) | medium | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic GIF comment concatenation allows DoS in Image.open() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-fc9g-5qg7-mf45 (CVE-2026-112891) | medium | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic GIF comment copying during save |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-p8hx-v2p6-rp84 (CVE-2026-96636) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Decompression-bomb protection bypass via multi-frame seek() in MPO and DCX (MpoImageFile.seek / DcxImageFile.see |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-rfgq-q3w2-pmv2 (CVE-2026-112898) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Image.quantize() with empty palette leaks uninitialized stack memory |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-vx6w-vv9f-6gvg (CVE-2026-112899) | medium | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock | Pillow: EPS load(scale) lets Ghostscript render past the decompression bomb limit |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-xgh8-jp6q-p5x8 (CVE-2026-112901) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: ReDoS in XbmImagePlugin: 512-byte file stalls Image.open() for minutes |

### 프로젝트: desktop-app-packaging-windows

`/home/dev/projects/desktop-app/packaging/windows`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | bottle@0.9.8 | PYSEC-2014-77 (CVE-2014-3137) | critical | 확인 | unknown |  | 0.031 | 0.10.12 | osv-scanner | requirements-win.txt | Bottle 0.10.x before 0.10.12, 0.11.x before 0.11.7, and 0.12.x before 0.12.6 does not properly limit content types, whic |
| P1 | 취약 의존성 | bottle@0.9.8 | PYSEC-2022-227 (CVE-2022-31799) | critical | 확인 | unknown |  | 0.021 | 0.12.20 | osv-scanner | requirements-win.txt | Bottle before 0.12.20 mishandles errors during early request binding. |
| P1 | 취약 의존성 | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 확인 | unknown |  |  | 2026.10.19 | osv-scanner | requirements-win.txt | certifi bundles emSign root CAs with compromised intermediate CA keys |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 확인 | unknown |  | 0.005 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Heap buffer overflow in ImagingJpegDecode |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 확인 | unknown |  | 0.006 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow multi-frame loaders can reuse stale native image storage after mode transitions |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Argument Injection in Ghostscript call, potentially leading into RCE |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Infinite loop in MIC n_frames when the embedded TIFF |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: NULL dereference in ImagingExpand via rank filters on zero-size images |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: TarIO negative size field causes infinite CPU-spin loop |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Out-of-bounds access in _imagingmorph on a zero-width image |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: APNG background disposal allocates full canvas before decompression bomb check |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: GIF seek keeps rejected size after DecompressionBombError, allowing DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 확인 | unknown |  |  | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Bundled libopenjp2 2.5.4 in all wheels since 11.1.0 carries OSV-2025-219 heap-buffer-overflow write reachable fr |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Double free in ImagingScaleAffine on calloc failure via Image.transform |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Heap over-read in WMF/EMF rendering via 16-bit dimension truncation (Windows builds) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: OOB read in TiffDecode.c tile and RGBA paths leaks heap memory into pixels |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: NULL pointer dereference in Image.merge via an unvalidated band 0 |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Infinite loop in PdfParser.rewrite_pages on page tree Parent cycle |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: PNG eXIf chunk makes EXIF parsing run in quadratic time |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Heap buffer overflow writing JPEG comment after ICC profile fills buffer |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Decompression bomb check bypass in SpiderImagePlugin.seek() leads to unbounded allocation DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: MSP RLE decoder expands a tiny file into unbounded memory |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Invalid free in FreeType glyph rendering when a stroker is active |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Quadratic-time DoS in PDF save_all (PdfParser.next_object_id) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow PDF append accepts malformed shared page-tree DAG causing resource exhaustion |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Unbounded recursion parsing a PDF page tree or trailer chain (incomplete fix for CVE-2026-42310) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: TIFF encoder ColorMap plane-size mismatch causes a heap out-of-bounds read |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: TiffDecode returns uninitialized memory as pixels for short JPEG strips |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 확인 | unknown |  |  | 13.0.0 | osv-scanner | requirements-win.txt |  Pillow: Memory disclosure and segfault in libtiff encoder via crafted TIFF tags |
| P2 | 취약 의존성 | bottle@0.9.8 | PYSEC-2021-129 (CVE-2020-28473) | medium | 확인 | unknown |  | 0.018 | 0.12.19 | osv-scanner | requirements-win.txt | The package bottle from 0 and before 0.12.19 are vulnerable to Web Cache Poisoning by using a vector called parameter cl |
| P2 | 취약 의존성 | opentelemetry-api@1.45.0 | GHSA-xcq7-p3pf-p88h (CVE-2026-114603) | medium | 확인 | unknown |  |  | 1.45.1 | osv-scanner | requirements-win.txt | OpenTelemetry Python: Unbounded tracestate parsing in opentelemetry-api |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-24rc-8hj2-v98c (CVE-2026-96638) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: BMP RLE decoder memory-amplification DoS via unbounded delta escape / absolute mode |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-254f-3936-288h (CVE-2026-112391) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: PdfParser can recurse without limit in get_value() and linearize_page_tree() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4558-3h8r-v8xp (CVE-2026-112394) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: P;2L and P;4L decoders may read 1 to 3 bytes past the passed buffer size |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-462x-pgg6-55fp (CVE-2026-112395) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow tiled-TIFF decoder reads past tile buffer in copy4 (Unpack.c:1290) |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rm8-3hmm-39fg (CVE-2026-96641) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Reachable undefined behavior in native integer operations, potentially leading to denial of service or logic int |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rr5-89j8-mwwm (CVE-2026-112396) | medium | 확인 | unknown |  | 0.005 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Heap use-after-free when encoding TIFF to an in-memory buffer |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-74r2-7ff9-mjj2 (CVE-2026-112401) | medium | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Quadratic GIF comment concatenation allows DoS in Image.open() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-fc9g-5qg7-mf45 (CVE-2026-112891) | medium | 확인 | unknown |  | 0.004 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Quadratic GIF comment copying during save |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-p8hx-v2p6-rp84 (CVE-2026-96636) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Decompression-bomb protection bypass via multi-frame seek() in MPO and DCX (MpoImageFile.seek / DcxImageFile.see |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-rfgq-q3w2-pmv2 (CVE-2026-112898) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: Image.quantize() with empty palette leaks uninitialized stack memory |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-vx6w-vv9f-6gvg (CVE-2026-112899) | medium | 확인 | unknown |  |  | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: EPS load(scale) lets Ghostscript render past the decompression bomb limit |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-xgh8-jp6q-p5x8 (CVE-2026-112901) | medium | 확인 | unknown |  | 0.003 | 13.0.0 | osv-scanner | requirements-win.txt | Pillow: ReDoS in XbmImagePlugin: 512-byte file stalls Image.open() for minutes |
| P2 | 취약 의존성 | pygments@2.9.0 | PYSEC-2023-117 (CVE-2022-40896) | medium | 확인 | unknown |  | 0.005 | 2.15.0 | osv-scanner | requirements-win.txt | A ReDoS issue was discovered in pygments/lexers/smithy.py in pygments through 2.15.0 via SmithyLexer. |
| P3 | 취약 의존성 | pygments@2.9.0 | PYSEC-2026-2987 (CVE-2026-4539) | low | 확인 | unknown |  | 0.002 | 2.20.0 | osv-scanner | requirements-win.txt | Pygments has Regular Expression Denial of Service (ReDoS) due to Inefficient Regex for GUID Matching |

### 프로젝트: mobile-app-a-server

`/home/dev/projects/mobile-app-a/server`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P2 | 취약 의존성 | vite@8.3.2 | GHSA-587h-7wmj-h5pm (CVE-2026-112942) | high | 확인 | not-imported |  | 0.013 | 8.3.3 | osv-scanner | package-lock.json | launch-editor: 'fs.existsSync()' existence check can be bypassed on Windows |
| P2 | 취약 의존성 | vite@8.3.2 | GHSA-698v-4r3x-3vcv (CVE-2026-112943) | medium | 확인 | not-imported |  | 0.004 | 8.3.3 | osv-scanner | package-lock.json | launch-editor: escapeCmdArgs() omits % escaping on Windows |
| P2 | 취약 의존성 | vite@8.3.2 | GHSA-r825-w8mm-5pxw (CVE-2026-112944) | medium | 확인 | not-imported |  | 0.007 | 8.3.3 | osv-scanner | package-lock.json | launch-editor: Editor CLI flag misinterpretation causing arbitrary command execution for some editors |
| P2 | 취약 의존성 | vite@8.3.2 | GHSA-rq7h-c2jc-7f22 (CVE-2026-112946) | medium | 확인 | not-imported |  | 0.009 | 8.3.3 | osv-scanner | package-lock.json | Vite: Files outside 'server.fs.allow' could be served when project paths match system paths on non-Windows machine |
| P2 | 취약 의존성 | vite@8.3.2 | GHSA-vfpm-58rq-9qcg (CVE-2026-112947) | medium | 확인 | not-imported |  | 0.004 | 8.3.3 | osv-scanner | package-lock.json | Vite: First 4 bytes of files outside of 'server.fs' setting is exposed by '?vite-wasm-instance' |
| P3 | 취약 의존성 | vite@8.3.2 | GHSA-9jrq-w75r-8gcw (CVE-2026-112945) | low | 확인 | not-imported |  | 0.005 | 8.3.3 | osv-scanner | package-lock.json | Vite: Cross origin script execution through Vite custom middleware |

### 프로젝트: phoenix-saas

`/home/dev/projects/phoenix-saas`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 코드 패턴 | 코드 패턴 | EXS-CFG-001 | high | - | n/a |  |  |  | grep | config/config.exs:36 | 비밀 값 하드코딩 (secret_key_base / signing_salt) |
| P1 | 취약 의존성 | bandit@1.12.5 | EEF-CVE-2026-105659 (CVE-2026-105659) | high | 확인 | imported |  | 0.005 | 1.13.0 | osv-scanner, osv+hex_audit | mix.lock, mix.lock:2 | HTTP/2 blocked-send deadlines reset on every WINDOW_UPDATE, letting a trickle pin stream processes indefinitely in Bandi |
| P2 | 취약 의존성 | bandit@1.12.5 | EEF-CVE-2026-105660 (CVE-2026-105660) | medium | 확인 | imported |  | 0.005 | 1.13.0 | osv-scanner, osv+hex_audit | mix.lock, mix.lock:2 | Unvalidated HTTP/1 request-target authority lets a client choose conn.host and conn.port in Bandit |
| P2 | 취약 의존성 | decimal@3.1.1 | EEF-CVE-2026-97853 (CVE-2026-97853) | medium | 확인 | imported |  | 0.001 | 3.1.2 | osv-scanner, osv+hex_audit | mix.lock, mix.lock:8 | Unbounded allocation in decimal Decimal.round/3 driven by the places argument enables DoS |
| P2 | 취약 의존성 | plug_crypto@2.2.0 | EEF-CVE-2026-105963 (CVE-2026-105963) | medium | 확인 | imported |  |  | 2.2.1 | osv-scanner, osv+hex_audit | mix.lock, mix.lock:39 | Secret key base exposed in stack trace arguments on wrong-typed Plug.Crypto arguments |

### 프로젝트: py-tool-a

`/home/dev/projects/py-tool-a`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P2 | 취약 의존성 | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 확인 | not-imported |  |  | 2026.10.19 | osv-scanner | uv.lock | certifi bundles emSign root CAs with compromised intermediate CA keys |
| P2 | 취약 의존성 | opentelemetry-api@1.45.0 | GHSA-xcq7-p3pf-p88h (CVE-2026-114603) | medium | 확인 | not-imported |  |  | 1.45.1 | osv-scanner | uv.lock | OpenTelemetry Python: Unbounded tracestate parsing in opentelemetry-api |

### 프로젝트: py-tool-c

`/home/dev/projects/py-tool-c`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P2 | 취약 의존성 | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 확인 | not-imported |  |  | 2026.10.19 | osv-scanner | uv.lock | certifi bundles emSign root CAs with compromised intermediate CA keys |
| P2 | 취약 의존성 | opentelemetry-api@1.45.0 | GHSA-xcq7-p3pf-p88h (CVE-2026-114603) | medium | 확인 | not-imported |  |  | 1.45.1 | osv-scanner | uv.lock | OpenTelemetry Python: Unbounded tracestate parsing in opentelemetry-api |

### 프로젝트: workflow-engine

`/home/dev/projects/workflow-engine`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 비밀값 | 비밀값 | github-oauth | critical | - | n/a |  |  |  | trivy | build/dir5/dir6/file7.sh:5359 | GitHub OAuth Access Token (GitHub) — 값은 마스킹됨 |
| P1 | 비밀값 | 비밀값 | jwt-token | medium | - | n/a |  |  |  | trivy | build/dir5/auth.json:5 | JWT token (JWT) — 값은 마스킹됨 |
| P1 | 비밀값 | 비밀값 | jwt-token | medium | - | n/a |  |  |  | trivy | build/dir5/auth.json:6 | JWT token (JWT) — 값은 마스킹됨 |
| P2 | 취약 의존성 | certifi@2026.7.22 | PYSEC-2026-4320 | critical | 확인 | not-imported |  |  | 2026.10.19 | osv-scanner | uv.lock | certifi bundles emSign root CAs with compromised intermediate CA keys |
| P2 | 취약 의존성 | urllib3@2.7.0 | PYSEC-2026-4175 (CVE-2026-97687) | high | 확인 | not-imported |  | 0.002 | 2.8.0 | osv-scanner | uv.lock | urllib3: HTTPS proxy TLS configuration may be ignored or overridden |
| P2 | 취약 의존성 | urllib3@2.7.0 | PYSEC-2026-4177 (CVE-2026-97689) | high | 확인 | not-imported |  | 0.003 | 2.8.0 | osv-scanner | uv.lock | urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory |
| P2 | 취약 의존성 | opentelemetry-api@1.44.0 | GHSA-xcq7-p3pf-p88h (CVE-2026-114603) | medium | 확인 | not-imported |  |  | 1.45.1 | osv-scanner | uv.lock | OpenTelemetry Python: Unbounded tracestate parsing in opentelemetry-api |
| P2 | 취약 의존성 | urllib3@2.7.0 | PYSEC-2026-4176 (CVE-2026-97688) | medium | 확인 | not-imported |  | 0.003 | 2.8.0 | osv-scanner | uv.lock | urllib3: Chunked Deflate streaming can enter an infinite loop |

### 프로젝트: workflow-engine-tools-trainer

`/home/dev/projects/workflow-engine/tools/trainer`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P2 | 취약 의존성 | accelerate@1.14.0 | PYSEC-2026-3804 (CVE-2026-69112) | high | 확인 | not-imported |  | 0.002 |  | osv-scanner | requirements-train.txt | Accelerate path traversal and denial of service via sharded checkpoint weight_map entries |
| P2 | 취약 의존성 | torch@2.10.0+cu128 | GHSA-rrmf-rvhw-rf47 (CVE-2025-3000) | medium | 확인 | imported |  | 0.002 | 2.13.0 | osv-scanner | requirements-train.txt | PyTorch is vulnerable to memory corruption through its torch.jit.script function |

### 프로젝트: wp-publisher

`/home/dev/projects/wp-publisher`

| 우선순위 | 종류 | 패키지 | ID | 심각도 | 검증 | 도달성 | KEV | EPSS | 수정 버전 | 출처 | 위치 | 설명 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-332p-7hrc-92wf (CVE-2026-112393) | critical | 확인 | imported |  | 0.005 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow in _tiffWriteProc when saving TIFF to BytesIO |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-8g5g-8vmr-9782 (CVE-2026-112403) | critical | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow in ImagingJpegDecode |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-v9pv-5gc8-w2m6 (CVE-2026-96639) | critical | 확인 | imported |  | 0.006 | 13.0.0 | osv-scanner | uv.lock | Pillow multi-frame loaders can reuse stale native image storage after mode transitions |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-w889-685w-c8fh (CVE-2026-112900) | critical | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Argument Injection in Ghostscript call, potentially leading into RCE |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-22hg-r758-rrw9 (CVE-2026-112390) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Infinite loop in MIC n_frames when the embedded TIFF |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-27h8-gf7j-v5hc (CVE-2026-112392) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: NULL dereference in ImagingExpand via rank filters on zero-size images |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-3j72-p6qg-6xp7 (CVE-2026-96642) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TarIO negative size field causes infinite CPU-spin loop |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-58r4-6rv3-gfh8 (CVE-2026-112397) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Out-of-bounds access in _imagingmorph on a zero-width image |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-5xm2-6676-qcp9 (CVE-2026-112399) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: APNG background disposal allocates full canvas before decompression bomb check |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-65qm-jvmh-6pqg (CVE-2026-112400) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: GIF seek keeps rejected size after DecompressionBombError, allowing DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-78g4-xqwv-q3g8 | high | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock | Pillow: Bundled libopenjp2 2.5.4 in all wheels since 11.1.0 carries OSV-2025-219 heap-buffer-overflow write reachable fr |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-7mwm-ghpf-9vrm (CVE-2026-112402) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Double free in ImagingScaleAffine on calloc failure via Image.transform |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-9v9v-9qvf-h2hj (CVE-2026-96644) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap over-read in WMF/EMF rendering via 16-bit dimension truncation (Windows builds) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-c6hw-5grf-ff96 (CVE-2026-112404) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: OOB read in TiffDecode.c tile and RGBA paths leaks heap memory into pixels |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-cp9v-662q-vvx9 (CVE-2026-112405) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: NULL pointer dereference in Image.merge via an unvalidated band 0 |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-f2g6-542v-9j58 (CVE-2026-112406) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Infinite loop in PdfParser.rewrite_pages on page tree Parent cycle |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g4qv-2jxx-769h (CVE-2026-96643) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: PNG eXIf chunk makes EXIF parsing run in quadratic time |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g7cr-3p24-7wf7 (CVE-2026-96778) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap buffer overflow writing JPEG comment after ICC profile fills buffer |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-g842-9rc4-69pw (CVE-2026-96637) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Decompression bomb check bypass in SpiderImagePlugin.seek() leads to unbounded allocation DoS |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-gg2r-wvfm-q9rx (CVE-2026-112892) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: MSP RLE decoder expands a tiny file into unbounded memory |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-j4m9-6w36-pw47 (CVE-2026-112893) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Invalid free in FreeType glyph rendering when a stroker is active |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-jg86-v3jv-hrpm (CVE-2026-112894) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic-time DoS in PDF save_all (PdfParser.next_object_id) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-mrfp-p49p-3hf2 (CVE-2026-96640) | high | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow PDF append accepts malformed shared page-tree DAG causing resource exhaustion |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-p4wg-p73j-c528 (CVE-2026-112895) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Unbounded recursion parsing a PDF page tree or trailer chain (incomplete fix for CVE-2026-42310) |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-pchr-8j38-3x4p (CVE-2026-112896) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TIFF encoder ColorMap plane-size mismatch causes a heap out-of-bounds read |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-q45j-58j2-45rg (CVE-2026-112897) | high | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: TiffDecode returns uninitialized memory as pixels for short JPEG strips |
| P1 | 취약 의존성 | pillow@12.3.0 | GHSA-xvh5-g6gv-559v (CVE-2026-112902) | high | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock |  Pillow: Memory disclosure and segfault in libtiff encoder via crafted TIFF tags |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-24rc-8hj2-v98c (CVE-2026-96638) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: BMP RLE decoder memory-amplification DoS via unbounded delta escape / absolute mode |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-254f-3936-288h (CVE-2026-112391) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: PdfParser can recurse without limit in get_value() and linearize_page_tree() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4558-3h8r-v8xp (CVE-2026-112394) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: P;2L and P;4L decoders may read 1 to 3 bytes past the passed buffer size |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-462x-pgg6-55fp (CVE-2026-112395) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow tiled-TIFF decoder reads past tile buffer in copy4 (Unpack.c:1290) |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rm8-3hmm-39fg (CVE-2026-96641) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Reachable undefined behavior in native integer operations, potentially leading to denial of service or logic int |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-4rr5-89j8-mwwm (CVE-2026-112396) | medium | 확인 | imported |  | 0.005 | 13.0.0 | osv-scanner | uv.lock | Pillow: Heap use-after-free when encoding TIFF to an in-memory buffer |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-74r2-7ff9-mjj2 (CVE-2026-112401) | medium | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic GIF comment concatenation allows DoS in Image.open() |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-fc9g-5qg7-mf45 (CVE-2026-112891) | medium | 확인 | imported |  | 0.004 | 13.0.0 | osv-scanner | uv.lock | Pillow: Quadratic GIF comment copying during save |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-p8hx-v2p6-rp84 (CVE-2026-96636) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Decompression-bomb protection bypass via multi-frame seek() in MPO and DCX (MpoImageFile.seek / DcxImageFile.see |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-rfgq-q3w2-pmv2 (CVE-2026-112898) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: Image.quantize() with empty palette leaks uninitialized stack memory |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-vx6w-vv9f-6gvg (CVE-2026-112899) | medium | 확인 | imported |  |  | 13.0.0 | osv-scanner | uv.lock | Pillow: EPS load(scale) lets Ghostscript render past the decompression bomb limit |
| P2 | 취약 의존성 | pillow@12.3.0 | GHSA-xgh8-jp6q-p5x8 (CVE-2026-112901) | medium | 확인 | imported |  | 0.003 | 13.0.0 | osv-scanner | uv.lock | Pillow: ReDoS in XbmImagePlugin: 512-byte file stalls Image.open() for minutes |

## 검증 실패 (OSV 404)

없음.

## 다음 행동

스윕은 아무것도 수정하지 않았다. 아래 명령은 검토 후 직접 실행한다 (프로젝트별로 브랜치를 만들고 테스트를 돌릴 것).

**프로젝트 `course-slides-midterm-deck`**

```sh
cd /home/dev/projects/course-slides/midterm/deck
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `course-slides-midterm-deck-simple`**

```sh
cd /home/dev/projects/course-slides/midterm/deck-simple
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `course-slides-midterm-templates`**

```sh
cd /home/dev/projects/course-slides/midterm/templates
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `course-slides-w05-deck`**

```sh
cd /home/dev/projects/course-slides/w05/deck
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `course-slides-w06-deck`**

```sh
cd /home/dev/projects/course-slides/w06/deck
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `course-slides-w07-deck`**

```sh
cd /home/dev/projects/course-slides/w07/deck
npm audit fix
# image-size → 2.0.3 이상
# sharp → 0.35.5 이상
```

**프로젝트 `desktop-app`**

```sh
cd /home/dev/projects/desktop-app
pip install -U certifi==2026.10.19
pip install -U opentelemetry-api==1.45.1
pip install -U pillow==13.0.0
```

**프로젝트 `desktop-app-packaging-windows`**

```sh
cd /home/dev/projects/desktop-app/packaging/windows
pip install -U bottle==0.12.20
pip install -U certifi==2026.10.19
pip install -U opentelemetry-api==1.45.1
pip install -U pillow==13.0.0
pip install -U pygments==2.20.0
```

**프로젝트 `mobile-app-a-server`**

```sh
cd /home/dev/projects/mobile-app-a/server
npm audit fix
# vite → 8.3.3 이상
```

**프로젝트 `phoenix-saas`**

```sh
cd /home/dev/projects/phoenix-saas
mix deps.update bandit decimal plug_crypto
```

**프로젝트 `py-tool-a`**

```sh
cd /home/dev/projects/py-tool-a
pip install -U certifi==2026.10.19
pip install -U opentelemetry-api==1.45.1
```

**프로젝트 `py-tool-c`**

```sh
cd /home/dev/projects/py-tool-c
pip install -U certifi==2026.10.19
pip install -U opentelemetry-api==1.45.1
```

**프로젝트 `workflow-engine`**

```sh
cd /home/dev/projects/workflow-engine
pip install -U certifi==2026.10.19
pip install -U opentelemetry-api==1.45.1
pip install -U urllib3==2.8.0
```

**프로젝트 `workflow-engine-tools-trainer`**

```sh
cd /home/dev/projects/workflow-engine/tools/trainer
pip install -U accelerate
pip install -U torch==2.13.0
```

**프로젝트 `wp-publisher`**

```sh
cd /home/dev/projects/wp-publisher
pip install -U pillow==13.0.0
```

**비밀값**: 위치만 표시했다(값은 보고서에 없음). 해당 키를 즉시 폐기·재발급하고 git 히스토리에서도 제거한다.

