# AdGuard DNS Kakao AdBlock Filter
# AdGuard DNS 카카오 광고차단 필터

[한국어](#한국어) | [English](#english)

---

## 한국어

카카오/다음 광고 및 추적 도메인**만** 정밀 차단하면서 모든 정상 서비스는 보호하는 AdGuard DNS 필터입니다.

### 🎯 철학: 과차단 방지를 위한 정밀 차단

**정상 기능을 해치는 것보다 광고를 일부 놓치는 것이 낫습니다.**

- ✅ **차단**: 특정 패턴의 확인된 광고/추적 도메인만 차단
- ✅ **보호**: 모든 필수 카카오 서비스 보호 (로그인, 결제, 지도 등)
- ✅ **검증**: 실제 DNS 조회로 도메인 활성 상태 확인

### 🚀 빠른 시작

#### AdGuard DNS 서비스별 사용법

##### 1. AdGuard DNS (adguard-dns.io) - 퍼블릭 DNS
1. [adguard-dns.io](https://adguard-dns.io) 접속
2. 대시보드에서 "블랙리스트" 탭 선택
3. "커스텀 필터 추가" 클릭
4. 다음 URL 입력:
   ```
   https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/develop/kakao-adblock-production.txt
   ```
5. 필터 이름: "Kakao AdBlock" 입력 후 저장

##### 2. AdGuard Home - 셀프 호스팅
1. AdGuard Home 관리자 페이지 접속
2. "필터" → "DNS 블랙리스트" 이동
3. "블랙리스트 추가" → "URL 추가" 클릭
4. 위 GitHub raw URL 입력
5. 이름 설정 후 저장

##### 3. AdGuard 앱 (iOS/Android)
1. AdGuard 앱 설정 열기
2. "DNS 보호" → "DNS 필터링" → "DNS 필터" 선택
3. "사용자 정의 필터 추가" 탭
4. 위 URL 추가

#### 필터 직접 사용

1. **필터 다운로드**: [`kakao-adblock-production.txt`](kakao-adblock-production.txt)
2. **수동 추가**: 다운로드한 파일 내용을 복사하여 직접 붙여넣기
3. **자동 업데이트**: raw GitHub URL 사용 권장

#### 직접 필터 생성

```bash
# 의존성 설치
pip install dnspython

# 최신 데이터로 필터 생성
python3 scripts/collect_kakao_domains.py my-kakao-filter.txt

# 도메인 검증 (선택사항이지만 권장)
python3 scripts/validate_domains.py my-kakao-filter.txt --clean-filter validated-filter.txt
```

### 📊 현재 상태 (2025-09-28)

- **🚫 차단된 광고 도메인**: 37개 확인된 도메인
- **✅ 보호되는 서비스**: 48개 필수 도메인
- **📡 데이터 소스**: 5개 한국 필터 리스트
- **🔍 검증**: DNS 검증된 활성 도메인

#### 확인된 활성 도메인

2025-09-28 기준 **활성 확인된** 도메인:

- `ads.kakaocdn.net` → 27.0.236.25 (광고용 CDN)
- `display.ad.daum.net` → 211.183.211.30 (디스플레이 광고)
- `info.ad.daum.net` → 211.249.220.152 (광고 정보 서비스)

### 🛡️ 보호되는 서비스 (절대 차단 안 함)

**항상 보호되는** 필수 카카오 서비스:

#### 인증 및 핵심 서비스
- `kakao.com`, `accounts.kakao.com`, `kauth.kakao.com`
- `pay.kakao.com`, `map.kakao.com`, `talk.kakao.com`
- `developers.kakao.com`, `api.kakao.com`

#### 미디어 및 엔터테인먼트
- `melon.com` (음악 스트리밍)
- `brunch.co.kr` (블로그 플랫폼)
- `daum.net` (포털 사이트)

#### 비즈니스 및 생산성
- `business.kakao.com`, `work.kakao.com`
- `calendar.kakao.com`, `keep.kakao.com`

[48개 보호 도메인 전체 목록](scripts/collect_kakao_domains.py#L109-L191)

### 🤝 기여하기

#### 새로운 광고 도메인 신고

차단해야 할 카카오 광고 도메인을 발견하셨나요?

**[🐛 광고 도메인 신고](../../issues/new?template=report-ad-domain.md)**

### ⚠️ 중요 고지

**이 Repository는 비영리, 비상업적으로 LLM Agent (Claude, Codex, Gemini)를 사용하여 운영 중이므로 이들이 실수할 수 있음을 알려드립니다.**

자세한 내용은 [NOTICE.md](NOTICE.md)를 참고하세요.

### 📝 라이선스

**GNU GPL v3.0** - List-KR과의 호환성을 위해 GPL v3.0 라이선스 적용

- [List-KR](https://github.com/List-KR/List-KR) - GNU GPL v3.0
- [YousList](https://github.com/yous/YousList) - CC BY-SA 4.0

---

## English

A precision AdGuard DNS filter for blocking **only** Kakao/Daum advertising and tracking domains while preserving all legitimate services.

### 🎯 Philosophy: Precision Over Coverage

**Better to miss some ads than break legitimate functionality.**

- ✅ **BLOCKS**: Only confirmed advertising/tracking domains with specific patterns
- ✅ **PRESERVES**: All essential Kakao services (login, payments, maps, etc.)
- ✅ **VALIDATES**: Uses real DNS lookups to verify domain activity

### 🚀 Quick Start

#### How to Use with AdGuard DNS Services

##### 1. AdGuard DNS (adguard-dns.io) - Public DNS
1. Go to [adguard-dns.io](https://adguard-dns.io)
2. Navigate to your dashboard "Denylist" tab
3. Click "Add custom filter"
4. Enter this URL:
   ```
   https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/develop/kakao-adblock-production.txt
   ```
5. Name it "Kakao AdBlock" and save

##### 2. AdGuard Home - Self-hosted
1. Access your AdGuard Home admin panel
2. Go to "Filters" → "DNS blocklists"
3. Click "Add blocklist" → "Add a custom list"
4. Enter the GitHub raw URL above
5. Set a name and save

##### 3. AdGuard Apps (iOS/Android)
1. Open AdGuard app settings
2. Go to "DNS protection" → "DNS filtering" → "DNS filters"
3. Tap "Add custom filter"
4. Add the URL above

#### Direct Filter Usage

1. **Download the filter**: [`kakao-adblock-production.txt`](kakao-adblock-production.txt)
2. **Manual addition**: Copy and paste the file contents directly
3. **Auto-updates**: Use raw GitHub URL (recommended)

#### Generate Your Own Filter

```bash
# Install dependencies
pip install dnspython

# Generate filter with latest data
python3 scripts/collect_kakao_domains.py my-kakao-filter.txt

# Validate domains (optional but recommended)
python3 scripts/validate_domains.py my-kakao-filter.txt --clean-filter validated-filter.txt
```

### 📊 Current Status (2025-09-28)

- **🚫 Ad domains blocked**: 37 confirmed domains
- **✅ Protected services**: 48 essential domains
- **📡 Data sources**: 5 Korean filter lists
- **🔍 Validation**: DNS-verified active domains

#### Confirmed Active Domains

These domains are **verified active** as of 2025-09-28:

- `ads.kakaocdn.net` → 27.0.236.25 (CDN for ads)
- `display.ad.daum.net` → 211.183.211.30 (Display advertising)
- `info.ad.daum.net` → 211.249.220.152 (Ad information service)

### 🛡️ Protected Services (Never Blocked)

Essential Kakao services that are **always preserved**:

#### Authentication & Core Services
- `kakao.com`, `accounts.kakao.com`, `kauth.kakao.com`
- `pay.kakao.com`, `map.kakao.com`, `talk.kakao.com`
- `developers.kakao.com`, `api.kakao.com`

#### Media & Entertainment
- `melon.com` (music streaming)
- `brunch.co.kr` (blog platform)
- `daum.net` (portal site)

#### Business & Productivity
- `business.kakao.com`, `work.kakao.com`
- `calendar.kakao.com`, `keep.kakao.com`

[Full list of 48 protected domains](scripts/collect_kakao_domains.py#L109-L191)

### 🔧 Advanced Usage

#### Domain Validation

Validate which domains are actually active:

```bash
# Full validation report
python3 scripts/validate_domains.py kakao-filter.txt

# Generate cleaned filter with only active domains
python3 scripts/validate_domains.py kakao-filter.txt \
    --clean-filter active-only.txt \
    --removed-domains inactive-domains.txt

# Quick validation (5 workers, 3s timeout)
python3 scripts/validate_domains.py kakao-filter.txt -w 5 -t 3.0
```

#### Data Sources Configuration

Modify [`scripts/sources.json`](scripts/sources.json) to add/remove filter sources:

```json
{
  "sources": [
    {
      "name": "List-KR-3rdParty",
      "url": "https://raw.githubusercontent.com/List-KR/List-KR/master/adblocking/filters-share/3rd_domains.txt",
      "type": "adblock",
      "encoding": "utf-8"
    }
  ]
}
```

#### Pattern Customization

Adjust blocking patterns in [`sources.json`](scripts/sources.json):

```json
{
  "ad_keywords": [
    "ad\\.",           // ad.kakao.com
    "ads\\.",          // ads.daum.net
    "track\\.",        // track.kakao.com
    "analytics\\."     // analytics.daum.net
  ]
}
```

### 🤝 Contributing

#### Report New Ad Domains

Found a Kakao ad domain that should be blocked?

**[🐛 Report Ad Domain](../../issues/new?template=report-ad-domain.md)**

#### Validation Checklist

Before reporting, please verify:
- [ ] Domain contains 'kakao' or 'daum'
- [ ] Domain is specifically for advertising/tracking
- [ ] Blocking doesn't break legitimate functionality
- [ ] Domain is not already in the filter

#### Development Setup

```bash
# Clone repository
git clone https://github.com/seonghobae/AdGuardDNS_KakaoAdBlock.git
cd AdGuardDNS_KakaoAdBlock

# Install dependencies
pip install dnspython

# Run tests
python3 scripts/collect_kakao_domains.py test-filter.txt
python3 scripts/validate_domains.py test-filter.txt
```

### 📈 Data Sources

The filter combines data from multiple Korean ad-blocking sources:

1. **[List-KR](https://github.com/List-KR/List-KR)** - Korean website filters for AdGuard/uBlock
2. **[YousList](https://github.com/yous/YousList)** - Korean sites ad block filter
3. **Curated domains** - Manually verified advertising domains
4. **Community reports** - User-submitted domains via GitHub issues

### 🔍 How It Works

#### 1. Data Collection
- Fetches latest filter lists from Korean sources
- Extracts domains matching Kakao/Daum patterns
- Validates against whitelist of legitimate services

#### 2. Pattern Matching
```python
# Only blocks domains with BOTH:
# 1. Kakao/Daum pattern: kakao.com, daum.net, etc.
# 2. Ad keywords: ad., ads., track., pixel., analytics.
```

#### 3. DNS Validation
- Verifies domains are actually active
- Removes outdated/inactive domains
- Provides confidence scoring

#### 4. Precision Filtering
- Protects 48+ essential services
- Uses whitelist-first approach
- Prioritizes functionality over coverage

### 📊 Validation Reports

Each filter generation includes validation data:

```json
{
  "summary": {
    "total_domains": 37,
    "active_domains": 3,
    "success_rate": 8.11,
    "average_response_time_ms": 216.3
  }
}
```

Low success rates are **expected** - many historical ad domains are no longer active, which is actually good for filter accuracy.

### 🛠️ Technical Details

#### Filter Format
- **Format**: AdGuard DNS filter format
- **Syntax**: `||domain.com^` (block domain and all subdomains)
- **Updates**: Manual generation (planned: automated CI/CD)
- **Validation**: DNS lookups with 3 public DNS servers

#### Performance
- **Parallel DNS lookups**: Up to 10 concurrent workers
- **Timeout**: 5 seconds per domain (configurable)
- **Reliability**: Multiple DNS servers (Google, Cloudflare, OpenDNS)

#### Security
- **No false positives**: Whitelist prevents blocking legitimate services
- **Conservative approach**: Better to under-block than over-block
- **Community validation**: Public issue tracking for transparency

### ⚠️ Important Notice

**This repository is operated non-commercially using LLM Agents (Claude, Codex, Gemini) which may make mistakes.**

See [NOTICE.md](NOTICE.md) for details.

### 📝 License

**GNU GPL v3.0** - For compatibility with List-KR

#### Attribution
- [List-KR](https://github.com/List-KR/List-KR) - GNU GPL v3.0
- [YousList](https://github.com/yous/YousList) - CC BY-SA 4.0

See [NOTICE.md](NOTICE.md) for details.

### 🔗 Related Projects

- [List-KR](https://github.com/List-KR/List-KR) - Korean website filters
- [YousList](https://github.com/yous/YousList) - Korean ads filter
- [KakaoTalkAdBlock](https://github.com/blurfx/KakaoTalkAdBlock) - Desktop client adblock

---

### 📞 Support

- **🐛 Bug Reports**: [GitHub Issues](../../issues)
- **💡 Feature Requests**: [GitHub Discussions](../../discussions)
- **📧 Contact**: [GitHub Profile](https://github.com/seonghobae)

**Last Updated**: 2025-09-28 | **Filter Version**: 20250928
