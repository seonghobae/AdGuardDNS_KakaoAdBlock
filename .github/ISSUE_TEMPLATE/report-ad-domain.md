---
name: Report Kakao Ad Domain
about: Report a new Kakao/Daum advertising domain that should be blocked
title: '[AD-DOMAIN] Add domain: '
labels: ['enhancement', 'ad-domain', 'needs-validation']
assignees: ''
---

## Domain Information

**Domain to be blocked:** `example.ad.kakao.com`

**Service/App where you found this domain:**
- [ ] KakaoTalk Desktop
- [ ] KakaoTalk Mobile
- [ ] Kakao Web Services
- [ ] Daum Portal
- [ ] Other: _______________

**Evidence of advertising/tracking behavior:**
<!-- Describe how you identified this as an ad domain -->
- [ ] Loads advertising content
- [ ] Tracking/analytics requests
- [ ] Seen in network logs during ad display
- [ ] Other: _______________

## Validation Checklist

**Before submitting, please verify:**
- [ ] The domain contains 'kakao', 'daum', or related keywords
- [ ] The domain is specifically for advertising/tracking (not legitimate services)
- [ ] You've checked that blocking this domain doesn't break legitimate functionality
- [ ] The domain is not already in the filter list

## Additional Information

**Network evidence (optional):**
```
<!-- Paste network request logs, browser dev tools output, etc. -->

```

**Screenshots (optional):**
<!-- Attach screenshots showing the ad or network requests -->

**Browser/App version:**
- Browser:
- Version:
- OS:

## Domain Pattern Analysis

**Help us improve pattern detection:**
- Does this follow a known pattern? (e.g., `ad.*.kakao.com`, `track.*.daum.net`)
- Are there similar domains that should also be blocked?
- Any additional subdomains or variations you've noticed?

---

### For Maintainers

**Validation Tasks:**
- [ ] DNS lookup confirms domain exists
- [ ] Domain follows Kakao/Daum patterns
- [ ] Domain matches ad/tracking keywords
- [ ] Domain not in whitelist of legitimate services
- [ ] Test blocking doesn't break functionality
- [ ] Add to appropriate category in filter

**Related Issues:** #___

---

## About This Filter

This filter uses a **precision-first approach**:
- ✅ **BLOCKS**: Only confirmed advertising/tracking domains
- ✅ **PRESERVES**: Essential Kakao services (login, payments, etc.)
- ✅ **PHILOSOPHY**: Better to miss some ads than break legitimate functionality

**Protected services:** kakao.com, accounts.kakao.com, pay.kakao.com, map.kakao.com, and [48 other essential domains](https://github.com/seonghobae/AdGuardDNS_KakaoAdBlock/blob/main/scripts/collect_kakao_domains.py#L109-L191).