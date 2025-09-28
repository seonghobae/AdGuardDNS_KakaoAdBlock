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

##### 1. AdGuard 퍼블릭 DNS (무료, 커스텀 필터 불가)
- **DNS 서버 주소만 변경**: 기기의 DNS를 AdGuard 퍼블릭 서버로 변경
  - 일반: `94.140.14.14` / `94.140.15.15`
  - 가족 보호: `94.140.14.15` / `94.140.15.16`
- **주의**: 퍼블릭 DNS는 커스텀 필터를 추가할 수 없음
- **대안**: 이미 카카오 광고를 일부 차단하지만 완벽하지 않음

##### 2. AdGuard 개인 DNS (유료, 커스텀 URL 불가)
1. [adguard-dns.io](https://adguard-dns.io) 가입 (유료 구독 필요)
2. 대시보드 → "서버" → 원하는 서버 선택
3. "사용자 규칙"(User rules) 클릭
4. "새 규칙 추가" → 도메인 이름 입력
5. 필터 파일에서 도메인을 하나씩 복사하여 추가 (수동)
- **주의**: 커스텀 URL 블록리스트 추가 불가, 도메인 개별 입력만 가능
- **대안**: 기본 제공 블록리스트 선택 또는 AdGuard Home 사용

##### 3. AdGuard Home (무료 오픈소스, 셀프 호스팅)
1. [AdGuard Home 설치](https://github.com/AdguardTeam/AdGuardHome#getting-started)
2. 관리자 페이지 접속 (기본: http://localhost:3000)
3. "필터" → "DNS 블랙리스트" 이동
4. "블랙리스트 추가" → "URL 추가" 클릭
5. 위 URL 입력 후 저장

##### 4. AdGuard 앱 (부분 유료)
- **iOS**: DNS 필터링은 Pro 기능 (유료)
- **Android**: DNS 필터링은 무료, 커스텀 필터는 프리미엄 기능
1. AdGuard 앱 설정
2. "DNS 보호" → "DNS 필터링" → "DNS 필터"
3. "필터 추가" → URL 입력

#### 필터 직접 사용

1. **필터 다운로드**: [`kakao-adblock-production.txt`](kakao-adblock-production.txt)
2. **수동 추가**: 다운로드한 파일 내용을 복사하여 직접 붙여녣기
3. **자동 업데이트**: raw GitHub URL 사용 권장

### 🌐 다른 DNS 서비스에서 사용하기

#### ⚠️ 기본 필터 비활성화 및 단독 사용 (비권장)

카카오 광고만 정확히 차단하고 싶은 경우, 기본 필터를 비활성화하고 이 필터만 사용할 수 있습니다.

**주의**: 기본 필터를 끄면 일반적인 광고, 추적기, 악성 사이트 차단이 작동하지 않습니다. 보안상 권장하지 않으며, 특수한 목적이 있을 때만 사용하세요:

**AdGuard Home**:
1. "필터" → "DNS 블랙리스트"
2. 기본 필터 체크 해제 (AdGuard DNS filter 등)
3. 카카오 필터만 추가하여 사용

**Pi-hole**:
1. 모든 기본 리스트 제거:
   ```bash
   sudo sqlite3 /etc/pihole/gravity.db "DELETE FROM adlist"
   ```
2. 카카오 필터만 추가
3. "Tools" → "Update Gravity"

**NextDNS**:
1. 필터 없는 프로필 생성
2. Denylist에만 카카오 도메인 추가
3. 모든 블록리스트 비활성화

**ControlD**:
1. 모든 Native/3rd Party 필터 끄기
2. Custom Rules에만 카카오 도메인 추가

#### NextDNS (부분 무료)
- **문제점**: NextDNS는 커스텀 블록리스트 URL 추가를 공식 지원하지 않음
- **대안 1**: Denylist에 도메인 개별 추가 (수동)
  1. NextDNS 대시보드 → "Denylist"
  2. 필터 파일에서 도메인만 추출하여 붙여넣기
- **대안 2**: [GitHub](https://github.com/nextdns/blocklists)에 블록리스트 제안
- **대안 3**: nextdnsctl 도구 사용 (비공식, 위험 감수)

#### Pi-hole (무료 오픈소스)
1. Pi-hole 관리자 패널 접속
2. "Adlists" 메뉴 클릭
3. URL 필드에 다음 입력:
   ```
   https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/main/kakao-adblock-production.txt
   ```
4. "Add" 클릭 후 "Tools" → "Update Gravity"

#### Cloudflare Zero Trust (무료 체험)
1. [Zero Trust 대시보드](https://one.dash.cloudflare.com) 접속
2. "Gateway" → "Lists" → "Create list"
3. 필터에서 도메인 복사하여 CSV로 업로드
4. "Gateway" → "Firewall Policies" → DNS 정책 생성
5. 조건: "Domain in list" → 생성한 리스트 선택
6. 액션: "Block"
- **제한**: 무료 플랜 1,000개 항목, 유료 5,000개

#### ControlD (무료 플랜 있음)
1. ControlD 대시보드 → 프로필 편집
2. "Custom Rules" 섹션으로 이동
3. 필터에서 도메인 복사하여 추가
4. 와일드카드 지원: `*.kakaocdn.net`
- **장점**: 와일드카드 및 TLD 차단 가능

#### DNS.SB / Quad9 / OpenDNS
- **커스텀 필터 불가**: 단순 DNS 서버로 커스텀 차단 불가
- **대안**: AdGuard Home 또는 Pi-hole와 함께 사용

### 🔄 txt 파일 자동 읽기 지원 DNS 서비스

URL로 제공되는 txt 필터 파일을 자동으로 읽고 업데이트하는 서비스:

#### ✅ 완전 지원 (URL로 자동 업데이트)
- **AdGuard Home**: 블록리스트 URL 직접 추가, 주기적 자동 업데이트
- **Pi-hole**: Adlists에 URL 추가, gravity 업데이트로 적용
- **Technitium DNS**: Settings → Blocking → Quick Add에서 URL 추가
- **Blocky DNS**: 외부 http/https URL 지원
- **pfSense + pfBlockerNG**: URL 기반 필터 리스트 지원
- **OPNsense + Unbound**: 블록리스트 URL 구독 기능

#### 🛠️ 부분 지원 (수동 또는 제한적)
- **ControlD**: Custom Rules에 도메인 복사 (개별 추가)
- **Cloudflare Zero Trust**: CSV 업로드, 최대 1,000개 제한
- **RethinkDNS**: 미래 유료 플랜에서 지원 예정

#### ❌ 미지원
- **AdGuard DNS** (adguard-dns.io): User Rules로 개별 도메인만 가능
- **NextDNS**: 커스텀 URL 불가, Denylist로 수동 추가
- **기타 공공 DNS**: Quad9, Cloudflare 1.1.1.1 등

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

##### 1. AdGuard Public DNS (Free, No Custom Filters)
- **DNS-only solution**: Change your device DNS to AdGuard public servers
  - Standard: `94.140.14.14` / `94.140.15.15`
  - Family protection: `94.140.14.15` / `94.140.15.16`
- **Note**: Public DNS cannot add custom filters
- **Alternative**: Already blocks some Kakao ads but not comprehensive

##### 2. AdGuard Private DNS (Paid, No Custom URL Support)
1. Sign up at [adguard-dns.io](https://adguard-dns.io) (subscription required)
2. Dashboard → "Servers" → Select your server
3. Click "User rules"
4. "Add new rule" → Enter domain name
5. Copy domains from filter file and add one by one (manual)
- **Note**: Cannot add custom URL blocklists, only individual domain rules
- **Alternative**: Use pre-installed blocklists or AdGuard Home

##### 3. AdGuard Home (Free Open-source, Self-hosted)
1. [Install AdGuard Home](https://github.com/AdguardTeam/AdGuardHome#getting-started)
2. Access admin panel (default: http://localhost:3000)
3. Go to "Filters" → "DNS blocklists"
4. Click "Add blocklist" → "Add a custom list"
5. Enter the URL above and save

##### 4. AdGuard Apps (Partially Paid)
- **iOS**: DNS filtering is a Pro feature (paid)
- **Android**: DNS filtering is free, custom filters are premium
1. Open AdGuard app settings
2. "DNS protection" → "DNS filtering" → "DNS filters"
3. "Add filter" → Enter URL

#### Direct Filter Usage

1. **Download the filter**: [`kakao-adblock-production.txt`](kakao-adblock-production.txt)
2. **Manual addition**: Copy and paste the file contents directly
3. **Auto-updates**: Use raw GitHub URL (recommended)

### 🌐 Other DNS Services Usage

#### ⚠️ Disable Default Filters for Standalone Use (Not Recommended)

To block ONLY Kakao ads precisely, you can disable all default filters and use only this filter.

**Warning**: Disabling default filters removes protection against general ads, trackers, and malicious sites. This is not recommended for security reasons. Use only for specific purposes:

**AdGuard Home**:
1. "Filters" → "DNS blocklists"
2. Uncheck default filters (AdGuard DNS filter, etc.)
3. Add only Kakao filter

**Pi-hole**:
1. Remove all default lists:
   ```bash
   sudo sqlite3 /etc/pihole/gravity.db "DELETE FROM adlist"
   ```
2. Add only Kakao filter
3. "Tools" → "Update Gravity"

**NextDNS**:
1. Create profile without filters
2. Add only Kakao domains to Denylist
3. Disable all blocklists

**ControlD**:
1. Turn off all Native/3rd Party filters
2. Add only Kakao domains to Custom Rules

#### NextDNS (Partially Free)
- **Issue**: NextDNS doesn't officially support custom blocklist URLs
- **Alternative 1**: Add domains individually to Denylist (manual)
  1. NextDNS Dashboard → "Denylist"
  2. Extract domains from filter file and paste
- **Alternative 2**: Suggest blocklist on [GitHub](https://github.com/nextdns/blocklists)
- **Alternative 3**: Use nextdnsctl tool (unofficial, at your own risk)

#### Pi-hole (Free Open-source)
1. Access Pi-hole admin panel
2. Click "Adlists" menu
3. Enter URL in the field:
   ```
   https://raw.githubusercontent.com/seonghobae/AdGuardDNS_KakaoAdBlock/main/kakao-adblock-production.txt
   ```
4. Click "Add" then "Tools" → "Update Gravity"

#### Cloudflare Zero Trust (Free Tier Available)
1. Go to [Zero Trust Dashboard](https://one.dash.cloudflare.com)
2. "Gateway" → "Lists" → "Create list"
3. Copy domains from filter and upload as CSV
4. "Gateway" → "Firewall Policies" → Create DNS policy
5. Condition: "Domain in list" → Select your list
6. Action: "Block"
- **Limit**: Free plan 1,000 items, paid 5,000

#### ControlD (Free Plan Available)
1. ControlD Dashboard → Edit Profile
2. Navigate to "Custom Rules" section
3. Copy domains from filter and add
4. Wildcard support: `*.kakaocdn.net`
- **Advantage**: Supports wildcards and TLD blocking

#### DNS.SB / Quad9 / OpenDNS
- **No custom filters**: Simple DNS servers without custom blocking
- **Alternative**: Use with AdGuard Home or Pi-hole

### 🔄 DNS Services with Automatic txt File Import

Services that automatically read and update txt filter files from URLs:

#### ✅ Full Support (Auto-update from URL)
- **AdGuard Home**: Direct blocklist URL addition, periodic auto-updates
- **Pi-hole**: Add URL to Adlists, apply via gravity update
- **Technitium DNS**: Settings → Blocking → Quick Add for URL addition
- **Blocky DNS**: Supports external http/https URLs
- **pfSense + pfBlockerNG**: URL-based filter list support
- **OPNsense + Unbound**: Blocklist URL subscription feature

#### 🛠️ Partial Support (Manual or Limited)
- **ControlD**: Copy domains to Custom Rules (individual addition)
- **Cloudflare Zero Trust**: CSV upload, max 1,000 items limit
- **RethinkDNS**: Custom lists planned for future paid plans

#### ❌ Not Supported
- **AdGuard DNS** (adguard-dns.io): Only individual domains via User Rules
- **NextDNS**: No custom URLs, manual Denylist only
- **Other Public DNS**: Quad9, Cloudflare 1.1.1.1, etc.

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
