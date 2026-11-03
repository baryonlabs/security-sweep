# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org/lang/ko/)을 따릅니다.

## [0.2.0] - 2026-11-04

### 추가
- `coverage.py`: 점검 대상별 원자적 저널 기록 및 완성도 판정 (`coverage.json`, `manifest.json`) — 스캔 실패·미점검을 "취약점 0건"으로 오도하는 문제 방지
- `inventory.py`: 원격 서버에서 임의 코드 실행 없이 Python venv 메타데이터(`.dist-info`)만 수집(`collect`)하고 로컬에서 OSV 취약점을 조회(`import`)하는 인벤토리 반입 파이프라인
- `operations.py`: labops/Discord 연동을 위한 기계 판독형 `summary.json` 및 주간 비교(`diff.json`) 지원 — 신규·유지·미관측·해결 상태 추적
- 증거 기반 트리아지(`triage.json`): 발견 항목의 고유 근거 해시(`evidence_hash`)와 바인딩된 판정 재정의 체계
- 신규 단위 테스트: `test_operations.py`, `test_inventory.py` 추가 (총 32개 테스트)

### 변경
- `verify_cves.py` & `report.py`: OSV 미등재(404) 취약점도 원래 스캐너 우선순위를 보존하여 누락 방지 (`OSV 미등재` 절 분리)
- 도달성 우선순위 판정 보정: `govulncheck`의 검증된 호출 추적 근거가 있을 때만 P0 승격, grep 기반 단순 추정으로 인한 승격/강등 배제
- `SKILL.md` 및 `references/servers.md`: 커버리지 저널, 인벤토리 반입, 주간 diff 및 요약 워크플로 문서화

## [0.1.1] - 2026-10-23

### 추가
- `examples/dev-machine-2026-10-23`: 개발 머신 한 대를 스윕 → 한 프로젝트 검토 → 패치 → 재스캔(5건 → 1건)하는 과정을 가명 처리한 실제 보고서와 함께 정리

### 수정
- OSV 캐시를 동시에 쓸 때 임시 파일 이름이 충돌하던 문제
- shellcheck 경고 정리

## [0.1.0] - 2026-10-23

### 추가
- `security-sweep` 스킬: 한 문장 요청으로 루트·서버·이미지를 해석해 탐색 → 스캔 → 검증 → 도달성 → 보고 → Claude 분류까지 실행
- `discover.sh`: lockfile·매니페스트로 프로젝트와 생태계 판별 (npm, PyPI, Hex, Go, Cargo, Packagist, RubyGems, Maven), 중첩·이름 충돌 처리
- `sweep.sh`: osv-scanner(lockfile별), trivy fs(비밀·설정)·image·rootfs(ssh, 읽기 전용), govulncheck, elixir-security-audit 연동, 비밀값 원문 제거
- `verify_cves.py`: 모든 ID를 OSV API로 실재 검증, CVSS v3 점수 계산, CISA KEV·EPSS 보강, 캐시·오프라인 모드
- `reachability.py`: govulncheck · 취약 심볼 · import grep으로 called/imported/not-imported 판정
- `report.py`: P0~P3 우선순위, 중복 제거, `findings.json`·`REPORT.md`·단일 파일 `REPORT.html`
- 다언어 취약 fixture 6종, 통합·단위 테스트, CI
- Codex Security · `/security-review` · Claude Security 비교 인포그래픽

[0.2.0]: https://github.com/baryonlabs/security-sweep/releases/tag/v0.2.0
[0.1.1]: https://github.com/baryonlabs/security-sweep/releases/tag/v0.1.1
[0.1.0]: https://github.com/baryonlabs/security-sweep/releases/tag/v0.1.0
