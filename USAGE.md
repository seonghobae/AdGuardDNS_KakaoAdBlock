# Kakao AdBlock Filter Usage Guide

이 가이드는 Kakao AdBlock 필터를 AdGuard DNS에 설정하는 방법을 설명합니다.

## 필터 URL

다음 URL을 AdGuard DNS 사용자 정의 필터에 추가하세요:

```
https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/main/kakao-adblock-filter.txt
```

## AdGuard DNS 설정 방법

### 1. AdGuard Home 사용자

1. AdGuard Home 웹 인터페이스에 접속
2. **필터** → **DNS 차단 목록** 메뉴로 이동
3. **사용자 정의 필터링 규칙 추가** 클릭
4. 위의 필터 URL을 입력
5. **저장** 클릭

### 2. AdGuard DNS 서비스 사용자

1. [AdGuard DNS 대시보드](https://adguard-dns.io/dashboard/)에 로그인
2. **필터** 섹션으로 이동
3. **사용자 정의 규칙** 탭 선택
4. 위의 필터 URL을 추가하거나 필터 내용을 직접 복사하여 붙여넣기

### 3. AdGuard 브라우저 확장 프로그램

1. AdGuard 확장 프로그램 설정 열기
2. **필터** → **사용자 정의 필터** 메뉴로 이동
3. **사용자 정의 필터 추가** 클릭
4. 위의 필터 URL을 입력

## 차단되는 도메인 카테고리

이 필터는 다음과 같은 Kakao 관련 광고 도메인을 차단합니다:

- **Kakao 핵심 광고 도메인**: ad.kakao.com, track.kakao.com 등
- **Daum 광고 도메인**: ad.daum.net, info.ad.daum.net 등
- **KakaoTalk 광고**: KakaoTalk 앱 내 광고 관련 도메인
- **Kakao 서비스 광고**: KakaoPay, KakaoMap, KakaoStory 등의 광고
- **모바일 SDK**: 모바일 앱 광고 SDK 관련 도메인
- **추적 및 분석**: 사용자 추적 및 분석 도메인

## 필터 통계

- 총 차단 규칙: **92개**
- 자동 업데이트: **매일 00:00 UTC (09:00 KST)**
- 필터 만료: **1일**

## 문제 해결

### 일부 Kakao 서비스가 작동하지 않는 경우

특정 Kakao 서비스에 문제가 발생하면, 해당 도메인을 화이트리스트에 추가할 수 있습니다:

```
@@||문제되는도메인.kakao.com^
```

### 새로운 광고 도메인 발견 시

새로운 Kakao 광고 도메인을 발견하면 [이슈](../../issues)를 통해 신고해 주세요.

## 라이선스

이 필터는 MIT 라이선스 하에 배포됩니다.