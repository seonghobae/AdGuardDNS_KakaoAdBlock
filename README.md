# AdGuard DNS Kakao AdBlock Filter

A precision AdGuard DNS filter for blocking **only** Kakao/Daum advertising and tracking domains while preserving all legitimate services.

## 🎯 Philosophy: Precision Over Coverage

**Better to miss some ads than break legitimate functionality.**

- ✅ **BLOCKS**: Only confirmed advertising/tracking domains with specific patterns
- ✅ **PRESERVES**: All essential Kakao services (login, payments, maps, etc.)
- ✅ **VALIDATES**: Uses real DNS lookups to verify domain activity

## 🚀 Quick Start

### Direct Filter Usage

1. **Download the filter**: [`kakao-adblock-production.txt`](kakao-adblock-production.txt)
2. **Add to AdGuard DNS**: Copy the URL and add as custom filter
3. **Alternative**: Use raw GitHub URL for auto-updates

### Generate Your Own Filter

```bash
# Install dependencies
pip install dnspython

# Generate filter with latest data
python3 scripts/collect_kakao_domains.py my-kakao-filter.txt

# Validate domains (optional but recommended)
python3 scripts/validate_domains.py my-kakao-filter.txt --clean-filter validated-filter.txt
```

## 📊 Current Status (2025-09-28)

- **🚫 Ad domains blocked**: 37 confirmed domains
- **✅ Protected services**: 48 essential domains
- **📡 Data sources**: 5 Korean filter lists
- **🔍 Validation**: DNS-verified active domains

### Confirmed Active Domains

These domains are **verified active** as of 2025-09-28:

- `ads.kakaocdn.net` → 27.0.236.25 (CDN for ads)
- `display.ad.daum.net` → 211.183.211.30 (Display advertising)
- `info.ad.daum.net` → 211.249.220.152 (Ad information service)

## 🛡️ Protected Services (Never Blocked)

Essential Kakao services that are **always preserved**:

### Authentication & Core Services
- `kakao.com`, `accounts.kakao.com`, `kauth.kakao.com`
- `pay.kakao.com`, `map.kakao.com`, `talk.kakao.com`
- `developers.kakao.com`, `api.kakao.com`

### Media & Entertainment
- `melon.com` (music streaming)
- `brunch.co.kr` (blog platform)
- `daum.net` (portal site)

### Business & Productivity
- `business.kakao.com`, `work.kakao.com`
- `calendar.kakao.com`, `keep.kakao.com`

[Full list of 48 protected domains](scripts/collect_kakao_domains.py#L109-L191)

## 🔧 Advanced Usage

### Domain Validation

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

### Data Sources Configuration

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

### Pattern Customization

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

## 🤝 Contributing

### Report New Ad Domains

Found a Kakao ad domain that should be blocked?

**[🐛 Report Ad Domain](../../issues/new?template=report-ad-domain.md)**

### Validation Checklist

Before reporting, please verify:
- [ ] Domain contains 'kakao' or 'daum'
- [ ] Domain is specifically for advertising/tracking
- [ ] Blocking doesn't break legitimate functionality
- [ ] Domain is not already in the filter

### Development Setup

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

## 📈 Data Sources

The filter combines data from multiple Korean ad-blocking sources:

1. **[List-KR](https://github.com/List-KR/List-KR)** - Korean website filters for AdGuard/uBlock
2. **[YousList](https://github.com/yous/YousList)** - Korean sites ad block filter
3. **Curated domains** - Manually verified advertising domains
4. **Community reports** - User-submitted domains via GitHub issues

## 🔍 How It Works

### 1. Data Collection
- Fetches latest filter lists from Korean sources
- Extracts domains matching Kakao/Daum patterns
- Validates against whitelist of legitimate services

### 2. Pattern Matching
```python
# Only blocks domains with BOTH:
# 1. Kakao/Daum pattern: kakao.com, daum.net, etc.
# 2. Ad keywords: ad., ads., track., pixel., analytics.
```

### 3. DNS Validation
- Verifies domains are actually active
- Removes outdated/inactive domains
- Provides confidence scoring

### 4. Precision Filtering
- Protects 48+ essential services
- Uses whitelist-first approach
- Prioritizes functionality over coverage

## 📊 Validation Reports

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

## 🛠️ Technical Details

### Filter Format
- **Format**: AdGuard DNS filter format
- **Syntax**: `||domain.com^` (block domain and all subdomains)
- **Updates**: Manual generation (planned: automated CI/CD)
- **Validation**: DNS lookups with 3 public DNS servers

### Performance
- **Parallel DNS lookups**: Up to 10 concurrent workers
- **Timeout**: 5 seconds per domain (configurable)
- **Reliability**: Multiple DNS servers (Google, Cloudflare, OpenDNS)

### Security
- **No false positives**: Whitelist prevents blocking legitimate services
- **Conservative approach**: Better to under-block than over-block
- **Community validation**: Public issue tracking for transparency

## 📝 License

MIT License - See [LICENSE](LICENSE) for details.

## 🔗 Related Projects

- [List-KR](https://github.com/List-KR/List-KR) - Korean website filters
- [YousList](https://github.com/yous/YousList) - Korean ads filter
- [KakaoTalkAdBlock](https://github.com/blurfx/KakaoTalkAdBlock) - Desktop client adblock

---

## 📞 Support

- **🐛 Bug Reports**: [GitHub Issues](../../issues)
- **💡 Feature Requests**: [GitHub Discussions](../../discussions)
- **📧 Contact**: [GitHub Profile](https://github.com/seonghobae)

**Last Updated**: 2025-09-28 | **Filter Version**: 20250928
