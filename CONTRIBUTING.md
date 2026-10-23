# 기여 가이드

## 개발 환경

- bash (macOS 3.2 호환), Python 3.9+ (표준 라이브러리만), [osv-scanner](https://github.com/google/osv-scanner), [trivy](https://github.com/aquasecurity/trivy), shellcheck

```bash
bash test/run.sh
python3 -m unittest discover -s skills/security-sweep/scripts/tests
shellcheck skills/security-sweep/scripts/*.sh test/*.sh
```

## 새 생태계 / 스캐너 추가 체크리스트

1. `docs/PLAN.md`의 데이터 계약에 판정 파일과 raw 출력 경로 추가
2. `discover.sh` 판정 파일 목록, `sweep.sh` 스캔 단계 추가 (도구가 없으면 `tools.txt`에 skipped 기록)
3. `verify_cves.py` / `reachability.py`에 ID 수집과 import 패턴 추가
4. `test/fixtures/<eco>-app`에 **실제 공개 권고가 있는** 버전과 그 패키지를 쓰는 코드 추가 (OSV에서 200 확인)
5. `test/expected.txt`에 기대 ID와 도달성 추가, 단위 테스트 추가

## 원칙

- CVE·GHSA ID는 OSV에서 확인된 것만 씁니다. 지어낸 ID는 테스트의 "검증 실패" 확인용 `CVE-2099-00001` 하나뿐입니다.
- 출력에 비밀값 원문이 남으면 안 됩니다. 새 스캐너를 붙이면 마스킹을 먼저 확인하세요.
- GitHub push protection이 막는 토큰 형식(AWS 키, `ghp_` 등)은 fixture에 쓰지 않습니다.
- 서버 대상 기능은 읽기 전용이어야 하며 원격에 아무것도 설치하지 않습니다.

## 커밋·PR

`feat:`, `fix:`, `docs:`, `test:`, `ci:` 접두사를 쓰고, PR에 테스트 결과를 적어 주세요.
