# Caido HTTPQL Filters & Presets

A curated collection of saved [Caido](https://caido.io/) HTTPQL filters and presets exported for web security testing, bug bounty hunting, and traffic analysis.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Quick Reference Table](#quick-reference-table)
- [Filter Categories](#filter-categories)
  - [Noise Reduction & Asset Filtering](#1-noise-reduction--asset-filtering)
  - [Vulnerability Hunting (GF-Style HTTPQL)](#2-vulnerability-hunting-gf-style-httpql)
  - [Cache, Headers & Response Analysis](#3-cache-headers--response-analysis)
  - [Target Workflows & Custom Triage](#4-target-workflows--custom-triage)
- [How to Use in Caido](#how-to-use-in-caido)
- [Raw JSON Export](#raw-json-export)

---

## Overview

Caido uses **HTTPQL** (HTTP Query Language) to filter requests and responses in the HTTP History, Replay, and Automate tools. These presets help eliminate noise (images, CSS, JS fonts), highlight vulnerable query parameters (XSS, SSRF, SQLi, IDOR, RCE, open redirects), and filter specific security headers.

---

## Quick Reference Table

| Name | Alias | Target | Description |
| :--- | :--- | :--- | :--- |
| **No Images** | `no-images` | Request Ext | Hides all static image extensions (`.png`, `.jpg`, `.svg`, `.webp`, etc.) |
| **No Styling** | `no-styling` | Request Ext | Hides stylesheet and font files (`.css`, `.woff`, `.woff2`, `.ttf`, `.eot`) |
| **NoJs** | `nojs` | Request Path | Filters out JavaScript (`.js`) file requests |
| **middleware** | `middleware` | Request Path | Matches common static/media/CDN directories |
| **gf-redirect** | `redirect` | Request Query / Path | Detects potential Open Redirect parameter names and paths |
| **gf-interestingparams** | `iparams` | Request Query | Detects high-interest parameters (admin, debug, file, redirect, etc.) |
| **gf-xss** | `xss` | Request Query | Detects common Cross-Site Scripting (XSS) parameter names |
| **gf-ssti** | `ssti` | Request Query | Detects Server-Side Template Injection parameter names |
| **gf-sqli** | `sqli` | Request Query | Detects SQL Injection target parameter names |
| **gf-idor** | `idor` | Request Query | Detects Insecure Direct Object Reference parameters |
| **gf-ssrf** | `ssrf` | Request Query | Detects Server-Side Request Forgery parameters |
| **rce** | `rce` | Request Query | Detects Remote Code Execution / command execution parameters |
| **gf-cors** | `cr` | Response Header | Finds responses containing `Access-Control` headers |
| **text-plain** | `text-plain` | Request Header | Matches requests with `Content-Type: text/plain` |
| **cache-oracle** | `new-preset` | Response Header | Identifies potential Web Cache Deception / Cache Oracle responses |
| **nowaf-resp** | `nowaf-resp` | Response Body | Filters out standard WAF block pages |
| **OAuth flow** | `oauth-flow` | Host / Path | Tracks OAuth flow endpoints and consent screens |
| **curl-to-caido** | `curl-to-caido` | Request Header | Matches traffic tagged with custom `X-Researcher` header |

---

## Filter Categories

### 1. Noise Reduction & Asset Filtering

#### No Images
- **Alias:** `no-images`
- **Purpose:** Strips away image file requests from your HTTP history to keep your proxy log clean.
```httpql
(req.ext.nlike:"%.apng" AND req.ext.nlike:"%.avif" AND req.ext.nlike:"%.gif" AND req.ext.nlike:"%.jpg" AND req.ext.nlike:"%.jpeg" AND req.ext.nlike:"%.pjpeg" AND req.ext.nlike:"%.pjp" AND req.ext.nlike:"%.png" AND req.ext.nlike:"%.svg" AND req.ext.nlike:"%.webp" AND req.ext.nlike:"%.bmp" AND req.ext.nlike:"%.ico" AND req.ext.nlike:"%.cur" AND req.ext.nlike:"%.tif" AND req.ext.nlike:"%.tiff")
```

#### No Styling
- **Alias:** `no-styling`
- **Purpose:** Strips away CSS stylesheets and web font assets.
```httpql
(req.ext.nlike:"%.css" AND req.ext.nlike:"%.woff" AND req.ext.nlike:"%.woff2" AND req.ext.nlike:"%.ttf" AND req.ext.nlike:"%.eot")
```

#### NoJs
- **Alias:** `nojs`
- **Purpose:** Excludes client-side JavaScript file requests.
```httpql
req.path.ncont:".js"
```

#### Middleware & Static Routes
- **Alias:** `middleware`
- **Purpose:** Matches paths containing media, static assets, downloads, uploads, or CDN folders.
```httpql
req.path.regex:"(?i)(media|images|image|static|assets|docs|download|downloads|files|file|content|cdn|proxy|uploads)"
```

---

### 2. Vulnerability Hunting (GF-Style HTTPQL)

#### gf-redirect (Open Redirect)
- **Alias:** `redirect`
- **Purpose:** Matches URL query parameters and paths commonly vulnerable to Open Redirects (e.g. `next=`, `url=`, `redirect_uri=`, `returnTo=`).
```httpql
req.query.regex:"(?i)(Lmage_url=|Open=|callback=|cgi-bin\/redirect.cgi|checkout=|checkout_url=|continue=|data=|dest=|destination=|dir=|domain=|feed=|file=|file_name=|file_url=|folder=|folder_url=|forward=|from_url=|go=|goto=|host=|html=|image_url=|img_url=|load_file=|load_url=|login_url=|logout=|navigation=|next=|next_page=|out=|page=|page_url=|path=|port=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|reference=|return=|returnTo=|return_path=|return_to=|return_url=|rt=|rurl=|show=|site=|target=|to=|uri=|url=|val=|validate=|view=|window=)" OR req.path.regex:"(?i)cgi-bin\/redirect.cgi"
```

#### gf-interestingparams (High-Value Parameters)
- **Alias:** `iparams`
- **Purpose:** Highlights sensitive administrative, debugging, execution, navigation, and configuration parameters across requests.
```httpql
req.query.regex:"(?i)(template=|preview=|id=|view=|activity=|name=|content=|redirect=|[&?]access[&=]|[&?]admin[&=]|[&?]dbg[&=]|[&?]debug[&=]|[&?]edit[&=]|[&?]grant[&=]|[&?]test[&=]|[&?]alter[&=]|[&?]clone[&=]|[&?]create[&=]|[&?]delete[&=]|[&?]disable[&=]|[&?]enable[&=]|[&?]exec[&=]|[&?]execute[&=]|[&?]load[&=]|[&?]make[&=]|[&?]modify[&=]|[&?]rename[&=]|[&?]reset[&=]|[&?]shell[&=]|[&?]toggle[&=]|[&?]adm[&=]|[&?]root[&=]|[&?]cfg[&=]|[&?]dest[&=]|[&?]redirect[&=]|[&?]uri[&=]|[&?]path[&=]|[&?]continue[&=]|[&?]url[&=]|[&?]window[&=]|[&?]next[&=]|[&?]data[&=]|[&?]reference[&=]|[&?]site[&=]|[&?]html[&=]|[&?]val[&=]|[&?]validate[&=]|[&?]domain[&=]|[&?]callback[&=]|[&?]return[&=]|[&?]feed[&=]|[&?]host[&=]|[&?]port[&=]|[&?]to[&=]|[&?]out[&=]|[&?]view[&=]|[&?]dir[&=]|[&?]show[&=]|[&?]navigation[&=]|[&?]open[&=]|[&?]file[&=]|[&?]document[&=]|[&?]folder[&=]|[&?]pg[&=]|[&?]php_path[&=]|[&?]style[&=]|[&?]doc[&=]|[&?]img[&=]|[&?]filename[&=]|id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=|sel=|results=|sleep=|fetch=|order=|keyword=|column=|field=|delete=|string=|number=|filter=|[&?]callback=|[&?]cgi-bin\/redirect.cgi|[&?]checkout=|[&?]checkout_url=|[&?]continue=|[&?]data=|[&?]dest=|[&?]destination=|[&?]dir=|[&?]domain=|[&?]feed=|[&?]file=|[&?]file_name=|[&?]file_url=|[&?]folder=|[&?]folder_url=|[&?]forward=|[&?]from_url=|[&?]go=|[&?]goto=|[&?]host=|[&?]html=|[&?]image_url=|[&?]img_url=|[&?]load_file=|[&?]load_url=|[&?]login_url=|[&?]logout=|[&?]navigation=|[&?]next=|[&?]next_page=|[&?]Open=|[&?]out=|[&?]page_url=|[&?]path=|[&?]port=|[&?]redir=|[&?]redirect=|[&?]redirect_to=|[&?]redirect_uri=|[&?]redirect_url=|[&?]reference=|[&?]return=|[&?]return_path=|[&?]return_to=|[&?]returnTo=|[&?]return_url=|[&?]rt=|[&?]rurl=|[&?]show=|[&?]site=|[&?]target=|[&?]to=|[&?]uri=|[&?]url=|[&?]val=|[&?]validate=|[&?]view=|[&?]window=|daemon=|upload=|dir=|execute=|download=|log=|ip=|cli=|cmd=|file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|id=|user=|account=|number=|order=|no=|doc=|key=|email=|group=|profile=|edit=|report=|access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|config=)"
```

#### gf-xss (Cross-Site Scripting)
- **Alias:** `xss`
- **Purpose:** Identifies parameters frequently reflected in HTML responses (e.g. `q=`, `search=`, `callback=`, `keyword=`).
```httpql
req.query.regex:"(?i)(q=|s=|search=|lang=|keyword=|query=|page=|keywords=|year=|view=|email=|type=|name=|p=|callback=|jsonp=|api_key=|api=|password=|email=|emailto=|token=|username=|csrf_token=|unsubscribe_token=|id=|item=|page_id=|month=|immagine=|list_type=|url=|terms=|categoryid=|key=|l=|begindate=|enddate=)"
```

#### gf-ssti (Server-Side Template Injection)
- **Alias:** `ssti`
- **Purpose:** Matches template render and preview parameter names.
```httpql
req.query.regex:"(?i)(template=|preview=|id=|view=|activity=|name=|content=|redirect=)"
```

#### gf-sqli (SQL Injection)
- **Alias:** `sqli`
- **Purpose:** Identifies database query parameters (sort, filter, order, column, search, where, etc.).
```httpql
req.query.regex:"(?i)(id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=|sel=|results=|sleep=|fetch=|order=|keyword=|column=|field=|delete=|user=|string=|number=|category=|filter=)"
```

#### gf-idor (Insecure Direct Object References)
- **Alias:** `idor`
- **Purpose:** Isolates object identifiers, user IDs, account numbers, and document references.
```httpql
req.query.regex:"(?i)(id=|user=|account=|number=|order=|no=|doc=|key=|email=|group=|profile=|edit=|report=)"
```

#### gf-ssrf (Server-Side Request Forgery)
- **Alias:** `ssrf`
- **Purpose:** Finds parameters accepting URLs, hosts, domain names, file paths, and webhooks.
```httpql
req.query.regex:"(?i)(access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|dest=|redirect=|uri=|path=|continue=|url=|window=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|php_path=|style=|doc=|img=|filename=)"
```

#### rce (Remote Code Execution)
- **Alias:** `rce`
- **Purpose:** Identifies query parameters related to system command execution, CLI utilities, and daemon controls.
```httpql
req.query.regex:"(?i)(daemon=|upload=|dir=|download=|log=|ip=|cli=|cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|arg=|option=|load=|process=|step=|read=|function|req=|feature=|exe=|module=|payload=|run=|print=)"
```

#### gf-cors (CORS Configuration)
- **Alias:** `cr`
- **Purpose:** Filters responses returning CORS-related headers (`Access-Control-*`).
```httpql
resp.header.name.eq:"Access-Control"
```

---

### 3. Cache, Headers & Response Analysis

#### cache-oracle (Web Cache Deception / Cache Oracle)
- **Alias:** `new-preset`
- **Purpose:** Targets cache-related response headers (`cache`, `age`, `cf-cache-status`, `x-served-by`, etc.) while excluding uncacheable or session-setting responses.
```httpql
(resp.header.name.cont:"cache" or resp.header.name.cont:"age" or resp.header.name.cont:"x-cache" or resp.header.name.cont:"cf-cache-status" or resp.header.name.cont:"x-served-by" or resp.header.name.cont:"x-vercel-cache" or resp.header.name.cont:"x-nextjs-cache") and resp.header.value.ncont:"no-store" and resp.header.value.ncont:"private" and resp.header.name.ncont:"set-cookie"
```

#### text-plain
- **Alias:** `text-plain`
- **Purpose:** Isolates requests with `Content-Type: text/plain` (useful for API endpoints, webhook listeners, and CSRF bypass analysis).
```httpql
req.header["Content-type"].cont:"text/plain"
```

#### nowaf-resp (Bypass / Non-Blocked Responses)
- **Alias:** `nowaf-resp`
- **Purpose:** Excludes common generic WAF block messages ("Sorry, you have been blocked", "Request blocked") from responses.
```httpql
resp.body.ncont:"Sorry, you have been blocked" AND resp.body.ncont:"Request blocked"
```

---

### 4. Target Workflows & Custom Triage

#### OAuth Flow (Moonpig & Google Auth)
- **Alias:** `oauth-flow`
- **Purpose:** Tracks and monitors OAuth authorization requests, consent screens, and token handoffs.
```httpql
req.host.cont:"moonpig" OR (req.path.cont:"/signin/oauth/v3/consent" AND resp.header["location"].ncont:"https://accounts.google.com/") OR req.path.cont:"/o/oauth2/v2/auth"
```

#### curl-to-caido (Researcher Tagged Requests)
- **Alias:** `curl-to-caido`
- **Purpose:** Isolates requests originating from external scripts or curl invocations sending an `X-Researcher` tracking header.
```httpql
req.header.name.eq:"X-Researcher"
```

---

## How to Use in Caido

### Method 1: Using Filter Aliases in Search
In Caido's HTTP History or Replay search bar, prefix an alias with `preset:`:
```httpql
preset:no-images
```
Or combine multiple filters:
```httpql
preset:no-images AND preset:no-styling AND preset:xss
```

### Method 2: Creating a New Filter Preset in Caido
1. Navigate to **HTTP History** in Caido.
2. In the HTTPQL query input bar at the top, paste any filter clause from above.
3. Click the **Save / Bookmark** icon on the right end of the bar.
4. Set the **Name** and **Alias**, then save.

---

## Raw JSON Export

You can find the raw JSON export in [`filters.json`](./filters.json) or copy it directly below:

<details>
<summary>Click to expand Caido Filters JSON</summary>

```json
[
  {
    "id": "p:1",
    "name": "No Images",
    "alias": "no-images",
    "clause": "(req.ext.nlike:\"%.apng\" AND req.ext.nlike:\"%.avif\" AND req.ext.nlike:\"%.gif\" AND req.ext.nlike:\"%.jpg\" AND req.ext.nlike:\"%.jpeg\" AND req.ext.nlike:\"%.pjpeg\" AND req.ext.nlike:\"%.pjp\" AND req.ext.nlike:\"%.png\" AND req.ext.nlike:\"%.svg\" AND req.ext.nlike:\"%.webp\" AND req.ext.nlike:\"%.bmp\" AND req.ext.nlike:\"%.ico\" AND req.ext.nlike:\"%.cur\" AND req.ext.nlike:\"%.tif\" AND req.ext.nlike:\"%.tiff\")"
  },
  {
    "id": "p:2",
    "name": "No Styling",
    "alias": "no-styling",
    "clause": "(req.ext.nlike:\"%.css\" AND req.ext.nlike:\"%.woff\" AND req.ext.nlike:\"%.woff2\" AND req.ext.nlike:\"%.ttf\" AND req.ext.nlike:\"%.eot\")"
  },
  {
    "id": "g:1",
    "name": "NoJs",
    "alias": "nojs",
    "clause": "req.path.ncont:\".js\""
  },
  {
    "id": "g:2",
    "name": "gf-redirect",
    "alias": "redirect",
    "clause": "req.query.regex:\"(?i)(Lmage_url=|Open=|callback=|cgi-bin\\/redirect.cgi|checkout=|checkout_url=|continue=|data=|dest=|destination=|dir=|domain=|feed=|file=|file_name=|file_url=|folder=|folder_url=|forward=|from_url=|go=|goto=|host=|html=|image_url=|img_url=|load_file=|load_url=|login_url=|logout=|navigation=|next=|next_page=|out=|page=|page_url=|path=|port=|redir=|redirect=|redirect_to=|redirect_uri=|redirect_url=|reference=|return=|returnTo=|return_path=|return_to=|return_url=|rt=|rurl=|show=|site=|target=|to=|uri=|url=|val=|validate=|view=|window=)\" OR req.path.regex:\"(?i)cgi-bin\\/redirect.cgi\""
  },
  {
    "id": "g:3",
    "name": "gf-interestingparams",
    "alias": "iparams",
    "clause": "req.query.regex:\"(?i)(template=|preview=|id=|view=|activity=|name=|content=|redirect=|[&?]access[&=]|[&?]admin[&=]|[&?]dbg[&=]|[&?]debug[&=]|[&?]edit[&=]|[&?]grant[&=]|[&?]test[&=]|[&?]alter[&=]|[&?]clone[&=]|[&?]create[&=]|[&?]delete[&=]|[&?]disable[&=]|[&?]enable[&=]|[&?]exec[&=]|[&?]execute[&=]|[&?]load[&=]|[&?]make[&=]|[&?]modify[&=]|[&?]rename[&=]|[&?]reset[&=]|[&?]shell[&=]|[&?]toggle[&=]|[&?]adm[&=]|[&?]root[&=]|[&?]cfg[&=]|[&?]dest[&=]|[&?]redirect[&=]|[&?]uri[&=]|[&?]path[&=]|[&?]continue[&=]|[&?]url[&=]|[&?]window[&=]|[&?]next[&=]|[&?]data[&=]|[&?]reference[&=]|[&?]site[&=]|[&?]html[&=]|[&?]val[&=]|[&?]validate[&=]|[&?]domain[&=]|[&?]callback[&=]|[&?]return[&=]|[&?]feed[&=]|[&?]host[&=]|[&?]port[&=]|[&?]to[&=]|[&?]out[&=]|[&?]view[&=]|[&?]dir[&=]|[&?]show[&=]|[&?]navigation[&=]|[&?]open[&=]|[&?]file[&=]|[&?]document[&=]|[&?]folder[&=]|[&?]pg[&=]|[&?]php_path[&=]|[&?]style[&=]|[&?]doc[&=]|[&?]img[&=]|[&?]filename[&=]|id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=|sel=|results=|sleep=|fetch=|order=|keyword=|column=|field=|delete=|string=|number=|filter=|[&?]callback=|[&?]cgi-bin\\/redirect.cgi|[&?]checkout=|[&?]checkout_url=|[&?]continue=|[&?]data=|[&?]dest=|[&?]destination=|[&?]dir=|[&?]domain=|[&?]feed=|[&?]file=|[&?]file_name=|[&?]file_url=|[&?]folder=|[&?]folder_url=|[&?]forward=|[&?]from_url=|[&?]go=|[&?]goto=|[&?]host=|[&?]html=|[&?]image_url=|[&?]img_url=|[&?]load_file=|[&?]load_url=|[&?]login_url=|[&?]logout=|[&?]navigation=|[&?]next=|[&?]next_page=|[&?]Open=|[&?]out=|[&?]page_url=|[&?]path=|[&?]port=|[&?]redir=|[&?]redirect=|[&?]redirect_to=|[&?]redirect_uri=|[&?]redirect_url=|[&?]reference=|[&?]return=|[&?]return_path=|[&?]return_to=|[&?]returnTo=|[&?]return_url=|[&?]rt=|[&?]rurl=|[&?]show=|[&?]site=|[&?]target=|[&?]to=|[&?]uri=|[&?]url=|[&?]val=|[&?]validate=|[&?]view=|[&?]window=|daemon=|upload=|dir=|execute=|download=|log=|ip=|cli=|cmd=|file=|document=|folder=|root=|path=|pg=|style=|pdf=|template=|php_path=|doc=|page=|name=|id=|user=|account=|number=|order=|no=|doc=|key=|email=|group=|profile=|edit=|report=|access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|config=)\""
  },
  {
    "id": "g:4",
    "name": "gf-xss",
    "alias": "xss",
    "clause": "req.query.regex:\"(?i)(q=|s=|search=|lang=|keyword=|query=|page=|keywords=|year=|view=|email=|type=|name=|p=|callback=|jsonp=|api_key=|api=|password=|email=|emailto=|token=|username=|csrf_token=|unsubscribe_token=|id=|item=|page_id=|month=|immagine=|list_type=|url=|terms=|categoryid=|key=|l=|begindate=|enddate=)\""
  },
  {
    "id": "g:5",
    "name": "gf-ssti",
    "alias": "ssti",
    "clause": "req.query.regex:\"(?i)(template=|preview=|id=|view=|activity=|name=|content=|redirect=)\""
  },
  {
    "id": "g:6",
    "name": "gf-sqli",
    "alias": "sqli",
    "clause": "req.query.regex:\"(?i)(id=|select=|report=|role=|update=|query=|user=|name=|sort=|where=|search=|params=|process=|row=|view=|table=|from=|sel=|results=|sleep=|fetch=|order=|keyword=|column=|field=|delete=|user=|string=|number=|category=|filter=)\""
  },
  {
    "id": "g:7",
    "name": "gf-idor",
    "alias": "idor",
    "clause": "req.query.regex:\"(?i)(id=|user=|account=|number=|order=|no=|doc=|key=|email=|group=|profile=|edit=|report=)\""
  },
  {
    "id": "g:8",
    "name": "gf-ssrf",
    "alias": "ssrf",
    "clause": "req.query.regex:\"(?i)(access=|admin=|dbg=|debug=|edit=|grant=|test=|alter=|clone=|create=|delete=|disable=|enable=|exec=|execute=|load=|make=|modify=|rename=|reset=|shell=|toggle=|adm=|root=|cfg=|dest=|redirect=|uri=|path=|continue=|url=|window=|next=|data=|reference=|site=|html=|val=|validate=|domain=|callback=|return=|page=|feed=|host=|port=|to=|out=|view=|dir=|show=|navigation=|open=|file=|document=|folder=|pg=|php_path=|style=|doc=|img=|filename=)\""
  },
  {
    "id": "g:9",
    "name": "middleware",
    "alias": "middleware",
    "clause": "req.path.regex:\"(?i)(media|images|image|static|assets|docs|download|downloads|files|file|content|cdn|proxy|uploads)\""
  },
  {
    "id": "g:10",
    "name": "text-plain",
    "alias": "text-plain",
    "clause": "req.header[\"Content-type\"].cont:\"text/plain\""
  },
  {
    "id": "g:11",
    "name": "cache-oracle",
    "alias": "new-preset",
    "clause": "(resp.header.name.cont:\"cache\" or resp.header.name.cont:\"age\" or resp.header.name.cont:\"x-cache\" or resp.header.name.cont:\"cf-cache-status\" or resp.header.name.cont:\"x-served-by\" or resp.header.name.cont:\"x-vercel-cache\" or resp.header.name.cont:\"x-nextjs-cache\") and resp.header.value.ncont:\"no-store\" and resp.header.value.ncont:\"private\" and resp.header.name.ncont:\"set-cookie\""
  },
  {
    "id": "g:12",
    "name": "OAuth flow (moonpig + Google consent/auth)",
    "alias": "oauth-flow",
    "clause": "req.host.cont:\"moonpig\" OR (req.path.cont:\"/signin/oauth/v3/consent\" AND resp.header[\"location\"].ncont:\"https://accounts.google.com/\") OR req.path.cont:\"/o/oauth2/v2/auth\""
  },
  {
    "id": "g:13",
    "name": "rce",
    "alias": "rce",
    "clause": "req.query.regex:\"(?i)(daemon=|upload=|dir=|download=|log=|ip=|cli=|cmd=|exec=|command=|execute=|ping=|query=|jump=|code=|reg=|do=|func=|arg=|option=|load=|process=|step=|read=|function|req=|feature=|exe=|module=|payload=|run=|print=)\""
  },
  {
    "id": "g:14",
    "name": "nowaf-resp",
    "alias": "nowaf-resp",
    "clause": "resp.body.ncont:\"Sorry, you have been blocked\" AND resp.body.ncont:\"Request blocked\""
  },
  {
    "id": "g:16",
    "name": "gf-cors",
    "alias": "cr",
    "clause": "resp.header.name.eq:\"Access-Control\""
  },
  {
    "id": "g:17",
    "name": "curl-to-caido",
    "alias": "curl-to-caido",
    "clause": "req.header.name.eq:\"X-Researcher\""
  }
]
```

</details>
