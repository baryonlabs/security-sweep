# 원샷 프롬프트 예시

그대로 복사해 쓰거나 경로·호스트만 바꾼다. `/security-sweep` 를 앞에 붙이지 않아도 트리거 문구("전체 보안 점검", "CVE 확인" 등)로 스킬이 실행된다.

## 1. 내 컴퓨터의 모든 프로젝트

```text
/security-sweep ~/work 아래 모든 프로젝트 취약점 점검해줘
```

```text
Sweep every project under ~/code for known vulnerabilities and give me the P0/P1 list.
```

## 2. 조직 저장소를 한 디렉터리에 체크아웃한 경우

```text
~/src/acme 에 클론해 둔 조직 저장소 전부 보안 스윕해줘. 깊이는 2단계까지만.
```

(→ `discover.sh ~/src/acme --max-depth 2`)

## 3. 현재 디렉터리만

```text
CVE 확인해줘
```

(roots 를 말하지 않으면 현재 디렉터리가 대상)

## 4. 서버 (ssh, 읽기 전용)

```text
서버 취약점 점검: deploy@web1.example.com, deploy@web2.example.com. 설치는 하지 말고 보고서만.
```

```text
Scan servers ops@10.0.0.11 and ops@10.0.0.12 over ssh (read-only, no sudo) plus ~/work/api.
```

호스트에 trivy 가 없으면 패키지 목록만 수집한다 — [servers.md](servers.md).

## 5. 컨테이너 이미지

```text
이미지 myapp:prod, worker:1.4.2 랑 지금 로컬에서 실행 중인 컨테이너 이미지 전부 취약점 점검해줘
```

(실행 중인 이미지 = `docker ps --format '{{.Image}}' | sort -u`)

## 6. 프로젝트 + 서버 + 이미지 한 번에

```text
/security-sweep ~/work/projects 전체랑 서버 web1, web2 (ssh), 이미지 myapp:prod 점검해줘
```

## 7. P0/P1 만

```text
모든 프로젝트 취약점 중에 P0, P1 만 근거랑 같이 보여줘. 나머지는 보고서에만.
```

## 8. 특정 CVE 가 우리에게 해당되는지

```text
CVE-2026-97853 이 ~/work 프로젝트들에 영향 있는지 확인해줘. 실제로 그 함수를 호출하는지까지.
```

ID 실재 여부는 OSV 조회로 판단하고, 영향 여부는 lockfile 버전 + 도달성 근거로 답한다.

## 9. CI / 네트워크 없이

```text
오프라인 모드로 이 저장소만 스캔해줘. 비밀 스캔은 빼고.
```

(→ `--no-secrets`, `verify_cves.py --offline`. 검증 칸은 `미검증(null)` 으로 남는다)

## 10. 매주 정기 실행

```text
매주 월요일 9시에 ~/work 전체 보안 스윕 돌리고 지난주 대비 신규 P0/P1 만 요약하도록 예약해줘
```

```text
Schedule a weekly security sweep of ~/work and summarize only new P0/P1 findings compared to last week.
```

## 11. 스윕 후 수정으로 넘기기

```text
방금 스윕 결과에서 billing-api 의 P0 만 브랜치 만들어서 최소 업그레이드로 고쳐줘
```

```text
elixir 프로젝트들은 elixir-security-audit 로 이어서 점검해줘
```
