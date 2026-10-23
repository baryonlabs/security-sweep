# 서버·컨테이너 점검 가이드

원칙: **읽기 전용, 사용자가 이름을 댄 호스트만, 원격 설치 금지, sudo 는 사용자가 명시할 때만.**

## 무엇을 보나

| 대상 | 방법 | 결과 파일 |
|------|------|-----------|
| 서버 OS 패키지 + 언어 패키지 | 원격에 trivy 가 있으면 `trivy rootfs --scanners vuln --format json /` | `raw/server/<host>.json` |
| 서버 (trivy 없음) | 패키지 목록만: `dpkg-query -W` / `rpm -qa` / `apk info -v` + `/etc/os-release` | `raw/server/<host>.packages.txt` |
| 컨테이너 이미지 | 로컬에서 `trivy image --format json NAME` | `raw/image/<safe-name>.json` |

서버 설정 감사(sshd_config, 방화벽, 열린 포트)와 런타임 침해 흔적은 범위 밖이다.

## ssh 요구 사항

- **키 인증**이 이미 설정되어 있어야 한다. 비밀번호 입력이 필요한 호스트는 실패로 기록하고 건너뛴다.
- 항상 `ssh -o BatchMode=yes -o ConnectTimeout=10 HOST '<command>'` — 프롬프트가 뜨지 않으므로 세션이 멈추지 않는다.
- 호스트 키를 처음 보는 호스트면 BatchMode 에서 실패한다. `StrictHostKeyChecking=no` 로 우회하지 않는다.
  사용자에게 `ssh HOST` 로 한 번 직접 접속해 지문을 확인하도록 안내한다.
- 접속 확인:

```bash
ssh -o BatchMode=yes -o ConnectTimeout=10 deploy@web1 'uname -a; cat /etc/os-release | head -3; command -v trivy'
```

- 점프 호스트·포트 등은 사용자의 `~/.ssh/config` 를 그대로 따른다 (호스트 별칭 사용 가능). config 에서 호스트를 골라 대상에 추가하지 않는다.

## trivy rootfs vs 패키지 목록 폴백

- **trivy 있음:** `trivy rootfs` 가 OS 패키지와 파일시스템의 언어 lockfile/바이너리까지 본다. 첫 실행은 원격에서 취약점 DB 를 내려받는다
  (네트워크 차단 서버는 실패할 수 있음 → tools.txt 에 note).
- **trivy 없음:** 원격에 설치하지 않는다. 패키지 목록만 가져온다. 이 목록은 OS 배포판·버전(`/etc/os-release`)과 함께 보고서에 "부분 점검"으로 표시된다.
  사용자가 원하면 다음 중 하나를 제안만 한다:
  - 서버 관리자가 직접 trivy 설치 (`apt`/`rpm` 공식 저장소)
  - 로컬에서 동일 버전 베이스 이미지를 `trivy image` 로 점검해 근사
  - 배포판 보안 도구: Debian/Ubuntu `debsecan`, RHEL `dnf updateinfo list --security`, Alpine `apk version -l '<'` (모두 서버 쪽 실행, 승인 필요)
- 서버 수정 명령(`apt-get install --only-upgrade pkg`, `dnf update --security`)은 보고서에 **제안**만 한다. 실행하지 않는다.

## sudo 주의

- 기본은 **sudo 없이** 실행한다. 일부 경로(`/root`, 다른 사용자 홈, 일부 `/var/lib`)는 못 읽어 결과가 덜 나올 수 있다 — 한계로 기록한다.
- 사용자가 "sudo 써도 돼" 라고 명시한 경우에만 `sudo -n trivy rootfs ...` (`-n`: 비밀번호 프롬프트 없이 실패).
  비밀번호를 대화로 받지 않는다.

## 컨테이너

- 실행 중인 이미지 목록 (읽기 전용):

```bash
docker ps --format '{{.Image}}' | sort -u
# 원격 docker 호스트
ssh -o BatchMode=yes HOST "docker ps --format '{{.Image}}'" | sort -u
```

- 이미지는 **로컬에서** `trivy image NAME` 으로 점검한다 (레지스트리 pull 이 필요할 수 있음 — 로그인 정보는 사용자의 docker 설정을 따른다).
  원격 호스트에만 있는 이미지는 그 호스트에 trivy 가 있을 때만 원격 실행하거나, 같은 태그를 로컬에서 pull 한다.
- `latest` 같은 가변 태그는 다이제스트(`docker inspect --format '{{index .RepoDigests 0}}' IMAGE`)를 보고서에 함께 적는다.
- 이미지 결과의 수정은 "베이스 이미지 갱신 + 재빌드"로 제안한다. 실행 중인 컨테이너 안에서 패키지를 업그레이드하라고 제안하지 않는다.

## Kubernetes

이 스킬은 클러스터를 직접 점검하지 않는다. 필요하면 `trivy k8s --report summary cluster` (현재 kubeconfig 컨텍스트, 읽기 권한 필요)를
사용자가 직접 실행하도록 안내만 한다. 클러스터 이미지 목록을 뽑아 `--image` 로 넘기는 방법도 있다:

```bash
kubectl get pods -A -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.image}{"\n"}{end}{end}' | sort -u
```
