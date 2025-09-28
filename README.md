# AdGuard DNS KakaoAdBlock

AdGuard DNS를 활용한 Kakao 광고 차단 프로젝트입니다.

## 개요

이 프로젝트는 AdGuard DNS 필터를 사용하여 Kakao 서비스의 광고를 효과적으로 차단하는 것을 목표로 합니다.

## 필터 사용법

### 빠른 시작

다음 URL을 AdGuard DNS 사용자 정의 필터에 추가하세요:

```
https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/main/kakao-adblock-filter.txt
```

자세한 설정 방법은 [USAGE.md](USAGE.md) 문서를 참고하세요.

### 필터 특징

- **자동 업데이트**: GitHub Actions를 통해 매일 자동 업데이트
- **포괄적 차단**: Kakao, Daum, KakaoTalk 등 모든 Kakao 서비스 광고 도메인 포함
- **92개 규칙**: 광고, 추적, 분석 도메인을 포괄적으로 차단
- **AdGuard DNS 호환**: 표준 AdGuard DNS 필터 문법 사용

## 프로젝트 구조

- `.github/workflows/` - GitHub Actions 자동화 워크플로우
- `kakao-adblock-filter.txt` - 메인 필터 파일
- `scripts/` - 필터 관리 및 검증 스크립트
- `USAGE.md` - 상세 사용 가이드
- `.cursor/` - AI 에이전트 작업 규칙 및 설정 (서브모듈)
- `.claude/` - AI 에이전트 규칙에 대한 심볼릭 링크

## 개발 가이드

프로젝트 개발 시 AGENTS.md 파일의 규칙을 따라주시기 바랍니다.