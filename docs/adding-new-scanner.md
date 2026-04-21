# Hướng dẫn: Thêm scanner mới vào Watchdog Worker

## Tổng quan kiến trúc

Watchdog Worker là file-based ingestion pipeline. Khi một file JSON được drop vào thư mục `worker/data/incoming/<scanner_name>/`, worker sẽ:

1. Detect file mới qua filesystem watcher
2. Xác định `scanner_name` từ tên thư mục con
3. Load adapter config tương ứng tại `worker/app/adapters/configs/<scanner_name>.yaml`
4. Parse + transform từng finding → Universal Data Model (UDM)
5. Upsert vào MongoDB (`vulnerabilities` + `assets` collection)
6. Archive file vào `worker/data/archive/<scanner_name>/`

**Kết luận: để thêm một scanner mới, bạn chỉ cần làm duy nhất một việc — tạo file YAML adapter config.**

---

## Bước 1: Phân tích cấu trúc JSON của scanner

Trước khi viết YAML, cần hiểu rõ report JSON của scanner có dạng gì. Cần trả lời 5 câu hỏi:

### Câu hỏi 1: Root structure — object hay array?

```jsonc
// Dạng json_object (root là object)
{ "vulnerabilities": [...], "host": "...", "scan_date": "..." }

// Dạng json_array (root là array)
[ { "plugin_id": 1, "host": "..." }, { ... } ]

// Dạng jsonl (mỗi dòng là 1 JSON object)
{"plugin_id": 1, "host": "..."}\n
{"plugin_id": 2, "host": "..."}\n
```

→ Điền vào `input.format`: `json_object` | `json_array` | `jsonl` | `auto`

### Câu hỏi 2: Path đến mảng findings?

```jsonc
// Nesting 1 cấp
{ "issues": [ {...}, {...} ] }
// → findings_path: "$.issues[*]"

// Nesting 2 cấp (như Invicti)
{ "export": { "scans": [ { "vulnerability_types": [{...}] } ] } }
// → findings_path: "$.export.scans[*].vulnerability_types[*]"

// Root là array (như Nuclei)
[ {...}, {...} ]
// → findings_path: "$[*]"
```

### Câu hỏi 3: Có cần JOIN với bảng phụ không?

Một số scanner tách metadata (host, port) ra một mảng riêng, findings chỉ lưu ID để reference.

```jsonc
// VD: findings có location_id, locations là mảng riêng
{
  "findings": [ { "name": "SQLi", "location_id": 42, ... } ],
  "locations": [ { "id": 42, "url": "https://example.com/login" } ]
}
```
→ Dùng `mode: nested_join` với `lookups`, sau đó truy cập bằng `lkp_<lookup_name>_<field>` trong mappings.

Nếu mỗi finding đã tự chứa đủ dữ liệu → dùng `mode: flat`.

### Câu hỏi 4: Cần inject context từ root không?

Một số trường như `scan_host`, `scan_date` chỉ có ở root object, không nằm trong từng finding. Dùng `context_inject` để đưa chúng vào, sau đó truy cập bằng `ctx_<name>`.

### Câu hỏi 5: Severity được encode như thế nào?

```jsonc
// Dạng string → map trực tiếp
"severity": "high"   // → severity: "$.severity"

// Dạng integer
"risk_factor": 3     // → dùng transform integer_map

// Dạng custom string
"risk": "CRITICAL"   // → dùng transform string_map
```

---

## Bước 2: Tạo thư mục incoming

```bash
mkdir -p worker/data/incoming/<scanner_name>
```

Worker chỉ nhận file từ thư mục con — tên thư mục chính là `scanner_name` được dùng để load adapter.

---

## Bước 3: Viết file YAML adapter

Tạo file tại: `worker/app/adapters/configs/<scanner_name>.yaml`

### Cấu trúc đầy đủ của YAML

```yaml
# ── 1. Tên scanner (phải trùng với tên file và tên thư mục incoming) ──
scanner: <scanner_name>
finding_type_default: vulnerability   # fallback nếu không có rule nào match

# ── 2. Input format ──
input:
  format: json_object   # json_object | json_array | jsonl | auto

# ── 3. Extraction — cách lấy danh sách findings từ file ──
extraction:
  mode: flat              # flat | nested_join | envelope
  findings_path: "$[*]"  # JSONPath đến mảng findings

  # [Tùy chọn] Chỉ dùng khi mode: nested_join
  lookups:
    <lookup_name>:
      source_path: "$.path.to.lookup.array[*]"   # path đến bảng phụ
      key_field:   "id"                            # primary key field trong bảng phụ
      join_on:     "$.finding_field_id"            # field trong finding dùng để JOIN

  # [Tùy chọn] Inject context từ root document vào mỗi finding
  context_inject:
    scan_host:  "$.root.path.to.host"
    scan_start: "$.root.path.to.date"

# ── 4. Finding type rules ── (áp dụng từ trên xuống, dừng ở rule đầu tiên match)
finding_type_rules:
  - if_tag_contains: ["cve", "exploit"]
    set_type: vulnerability
  - if_tag_contains: ["ssl", "tls", "weak_crypto"]
    set_type: ssl_finding
  - if_tag_contains: ["info", "detect"]
    set_type: exposure
  - if_category_equals: ["configuration", "misconfiguration"]
    set_type: misconfiguration
  - default: vulnerability

# ── 5. Required fields — finding bị bỏ qua nếu thiếu bất kỳ field nào ──
required_fields:
  - target.hostname
  - identity.standardized_rule_id
  - severity

# ── 6. Evidence size limits ──
evidence_limits:
  max_response_size_kb: 512
  max_raw_size_kb: 1024
  skip_binary_content: true

# ── 7. Mappings — ánh xạ từ finding raw → UDM fields ──
mappings:
  # -- Target --
  target.hostname:    "$.host"
  target.ip:          "$.ip"
  target.port:
    source: "$.port"
    transform:
      - type: cast_int
  target.url:         "$.url"
  target.protocol:    "$.protocol"

  # -- Identity --
  identity.standardized_rule_id: "$.plugin_id"  # ID duy nhất của rule/signature
  identity.raw_rule_id:          "$.plugin_id"
  identity.name:                 "$.plugin_name"
  identity.category:             "$.category"
  identity.cve:
    source: "$.cve"
    transform:
      - type: filter_by_prefix
        prefix: "CVE-"
  identity.cwe:       "$.cwe"
  identity.cvss_score:  "$.cvss_base_score"
  identity.cvss_vector: "$.cvss_vector"

  # -- Severity --
  severity: "$.severity"   # hoặc dùng transform nếu cần map

  # -- Evidence --
  evidence.request:      "$.request"
  evidence.response:     "$.response"
  evidence.matched_at:   "$.url"
  evidence.curl_command: "$.curl_command"
  evidence.raw:          "$"   # lưu toàn bộ finding raw

  # -- Meta --
  tags:       "$.tags"
  references: "$.references[*].url"
```

---

## Bước 4: Tham chiếu đầy đủ — các Transform có sẵn

| Transform | Dùng khi | Tham số |
|---|---|---|
| `passthrough` | Giữ nguyên value | — |
| `integer_map` | Severity là số nguyên | `map: {0: info, 1: low, 2: medium, 3: high, 4: critical}` |
| `string_map` | Severity là string custom | `map: {"CRITICAL": critical, "HIGH": high, ...}` |
| `regex_extract` | Trích xuất substring | `pattern`, `group`, `prefix`, `fallback_source`, `fallback_prefix` |
| `regex_replace` | Xóa/thay thế substring | `pattern`, `replacement` |
| `filter_by_prefix` | Lọc từ array theo prefix | `prefix: "CVE-"` |
| `filter_empty` | Loại bỏ null/empty trong array | — |
| `cast_int` | Convert string/float → int | — |
| `cast_str` | Convert → string | — |
| `split` | Tách string → array | `delimiter: ","` |
| `join` | Ghép array → string | `delimiter: ", "` |
| `slugify` | Chuẩn hóa thành slug | `prefix: "scanner:"` |
| `url_hostname_only` | Lấy hostname từ URL | — |
| `url_path_only` | Lấy path từ URL | — |
| `url_port_only` | Lấy port từ URL | — |
| `url_scheme_only` | Lấy scheme từ URL | — |
| `strip_scheme` | Xóa `https://` khỏi URL | — |
| `omit_keys` | Xóa một số key khỏi dict | `keys: ["password", "token"]` |

---

## Ví dụ thực tế: Nessus

### Cấu trúc JSON Nessus điển hình (`.nessus` export dạng JSON)

```jsonc
{
  "report": {
    "name": "My Scan",
    "report_hosts": [
      {
        "name": "192.168.1.10",
        "host-properties": { "HOST_START": "...", "host-ip": "192.168.1.10" },
        "report_items": [
          {
            "plugin_id": 10881,
            "plugin_name": "SSH Protocol Version 1 Session Key Retrieval",
            "plugin_family": "General",
            "port": 22,
            "protocol": "tcp",
            "severity": 3,
            "cvss3_base_score": 7.5,
            "cvss3_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "cve": ["CVE-2001-0572"],
            "description": "...",
            "solution": "...",
            "plugin_output": "...",
            "risk_factor": "High"
          }
        ]
      }
    ]
  }
}
```

### Trả lời 5 câu hỏi

1. **Root format**: `json_object` — root là object `{ "report": {...} }`
2. **Findings path**: Mỗi finding nằm trong `report.report_hosts[*].report_items[*]` → `"$.report.report_hosts[*].report_items[*]"`
3. **JOIN cần không?**: Có — `report_hosts` chứa hostname/IP, cần inject vào mỗi finding. Dùng `context_inject` không đủ (nhiều host), phải dùng `mode: nested_join` với `lookups`.
4. **Context**: Không cần inject từ root (hostname đã JOIN được).
5. **Severity**: Integer `0–4` → dùng `integer_map`.

### File YAML: `worker/app/adapters/configs/nessus.yaml`

```yaml
scanner: nessus
finding_type_default: vulnerability

input:
  format: json_object

extraction:
  mode: nested_join
  findings_path: "$.report.report_hosts[*].report_items[*]"

  lookups:
    host:
      # Mảng chứa thông tin host
      source_path: "$.report.report_hosts[*]"
      # Field dùng làm primary key trong bảng host
      key_field:   "name"
      # Field trong mỗi finding dùng để JOIN (cần inject từ parent trước)
      # → Nessus không có host_name trong report_item nên cần custom pre-processing
      # Trong trường hợp này có thể dùng context_inject thay thế nếu chỉ có 1 host

finding_type_rules:
  - if_tag_contains: ["cve"]
    set_type: vulnerability
  - if_tag_contains: ["ssl", "tls"]
    set_type: ssl_finding
  - if_tag_contains: ["info"]
    set_type: exposure
  - if_category_equals: ["configuration"]
    set_type: misconfiguration
  - default: vulnerability

required_fields:
  - target.hostname
  - identity.standardized_rule_id
  - severity

evidence_limits:
  max_response_size_kb: 512
  max_raw_size_kb: 1024

mappings:
  # Target — hostname JOIN từ lookup hoặc inject từ context
  target.hostname:  "$.lkp_host_name"    # kết quả JOIN: tên host (IP hoặc FQDN)
  target.ip:        "$.lkp_host_name"    # trong Nessus, host name thường là IP
  target.port:
    source: "$.port"
    transform:
      - type: cast_int
  target.protocol:  "$.protocol"

  # Identity
  identity.standardized_rule_id:
    source: "$.plugin_id"
    transform:
      - type: cast_str
      - type: slugify
        prefix: "nessus:"
  identity.raw_rule_id:  "$.plugin_id"
  identity.name:         "$.plugin_name"
  identity.category:     "$.plugin_family"
  identity.cve:
    source: "$.cve"
    transform:
      - type: passthrough
  identity.cvss_score:   "$.cvss3_base_score"
  identity.cvss_vector:  "$.cvss3_vector"

  # Severity — Nessus dùng integer 0-4
  severity:
    source: "$.severity"
    transform:
      - type: integer_map
        map:
          0: info
          1: low
          2: medium
          3: high
          4: critical

  # Evidence
  evidence.matched_at:   "$.lkp_host_name"
  evidence.raw:          "$"
  evidence.details_template: "$.description"

  tags:       "$.cve"
  references: "$.see_also"
```

> **Lưu ý về Nessus**: Cấu trúc `report_hosts[*].report_items[*]` là nested array 2 cấp. JSONPath `$.report.report_hosts[*].report_items[*]` sẽ flatten thành flat list các findings, **nhưng hostname từ `report_hosts.name` sẽ bị mất** vì findings không tự chứa trường này. Trong trường hợp này, cần export Nessus sang định dạng CSV hoặc API response có `host` field flatten sẵn trong mỗi finding. Hoặc cần viết custom pre-processor script để flatten trước khi drop vào `incoming/`.

---

## Bước 5: Test

```bash
# Copy file test vào incoming
cp my-nessus-export.json worker/data/incoming/nessus/

# Xem log worker ngay lập tức
docker compose logs worker --tail=20 -f
```

**Log thành công trông như này:**
```
INFO Processing nessus/my-nessus-export.json via engine (scanner=nessus)
INFO Archived my-nessus-export.json → my-nessus-export-20260420T...Z.json | processed=47 inserted=45 updated=2 assets=3
INFO Processed my-nessus-export.json | processed=47 inserted=45 updated=2 assets=3
```

**Log thất bại thường gặp và cách debug:**

| Log | Nguyên nhân | Fix |
|---|---|---|
| `processed=0 inserted=0` + "Empty file archived" | `findings_path` sai → extract được 0 findings | Kiểm tra lại JSONPath trong `extraction.findings_path` |
| `processed=N inserted=0` | `required_fields` không satisfy | Field `target.hostname`, `identity.standardized_rule_id`, hoặc `severity` đang `None` — kiểm tra mappings |
| `AdapterConfigError` | Không tìm thấy YAML | Tên file YAML phải trùng với tên thư mục `incoming/<name>` |
| `ValidationError` trong YAML | YAML syntax lỗi | Dùng [yaml.org/start](https://yaml.org/start.html) để validate |

**Kỹ thuật debug JSONPath nhanh:**
```python
# Chạy trong Python để test path trước khi viết YAML
import json
from jsonpath_ng.ext import parse

data = json.load(open("my-nessus-export.json"))
expr = parse("$.report.report_hosts[*].report_items[*]")
findings = [m.value for m in expr.find(data)]
print(f"Found {len(findings)} findings")
print(findings[0])  # Xem cấu trúc finding đầu tiên
```

---

## Checklist hoàn chỉnh

- [ ] Đã phân tích JSON: biết root format, findings path, cần JOIN hay không
- [ ] Tạo thư mục `worker/data/incoming/<scanner_name>/`
- [ ] Tạo file `worker/app/adapters/configs/<scanner_name>.yaml`
- [ ] `scanner:` trong YAML trùng với tên thư mục
- [ ] `required_fields` có thể satisfy được từ JSON (hostname, rule_id, severity đều có giá trị)
- [ ] Severity mapping đúng (ra một trong: `info`, `low`, `medium`, `high`, `critical`)
- [ ] Test với file thực tế, kiểm tra log `processed > 0`
- [ ] Rebuild worker container: `docker compose up -d --build worker`
