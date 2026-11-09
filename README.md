# Software Supply Chain Security Lab (SLSA & SBOM)

Dự án thực hành chuyên sâu về **An toàn chuỗi cung ứng phần mềm (Software Supply Chain Security)** tuân thủ các tiêu chuẩn công nghiệp quốc tế:
- **SBOM (Software Bill of Materials)**: Chuẩn **SPDX** (`spdx-json`) và **CycloneDX** (`cyclonedx-json`) sinh bởi Anchore Syft, quét lỗ hổng với Anchore Grype.
- **Sigstore Cosign**: Cơ chế ký số không cần khóa dài hạn (**Keyless Signing**) xác thực định danh OIDC GitHub Actions, chứng chỉ X.509 ngắn hạn từ Fulcio và ghi vết Rekor Transparency Log.
- **SLSA Framework (Level 3)**: Hardened pipeline, cô lập môi trường build, nguyên tắc đặc quyền tối thiểu, và tự động sinh chứng thực nguồn gốc xuất xứ **SLSA Provenance Attestation** với `slsa-framework/slsa-github-generator`.

---

## Cấu trúc Repository

```tree
.
├── .github/
│   └── workflows/
│       ├── sbom.yml               # Lab 1: Sinh SPDX & CycloneDX SBOM và quét lỗ hổng với Grype
│       ├── cosign-sign.yml        # Lab 2: Đóng gói, ký số Keyless Sigstore Cosign và xác thực
│       └── slsa-provenance.yml    # Lab 3: Hardened Build & SLSA Level 3 Provenance Generator
├── app.py                         # Module ứng dụng cho Lab 2
├── main.py                        # Module ứng dụng cho Lab 3
├── requirements.txt               # Danh mục phụ thuộc cho Syft phân tích SBOM
└── README.md
```

---

## Chi tiết các quy trình CI/CD Workflows

### 1. Workflow: Sinh và Phân tích SBOM (`sbom.yml`)
- **Bộ kích hoạt**: Push hoặc Pull Request vào nhánh `main`, `workflow_dispatch`.
- **Hành động**:
  - `anchore/sbom-action@v0.15.10`: Sinh `sbom.spdx.json` theo chuẩn SPDX.
  - `anchore/sbom-action@v0.15.10`: Sinh `sbom.cyclonedx.json` theo chuẩn CycloneDX.
  - `anchore/scan-action@v7`: Quét lỗ hổng an ninh trên tệp SBOM bằng Grype, xuất định dạng SARIF `results.sarif` và bảng tổng hợp CLI.
  - `actions/upload-artifact@v4`: Lưu trữ các tệp SBOM và báo cáo SARIF làm artifact.

### 2. Workflow: Ký số và Xác thực với Sigstore Cosign (`cosign-sign.yml`)
- **Bộ kích hoạt**: Push Git Tag `v*` (ví dụ `v1.0.0`), `workflow_dispatch`.
- **Hành động**:
  - Đóng gói artifact `release.tar.gz` và tính hash `release.tar.gz.sha256`.
  - Cài đặt Cosign qua `sigstore/cosign-installer@v4`.
  - Ký số Keyless: `cosign sign-blob` sử dụng GitHub Actions OIDC Token gửi tới Fulcio CA để nhận chứng chỉ X.509 tạm thời và ghi log vào Rekor.
  - Xác thực chữ ký: `cosign verify-blob` kiểm tra chứng chỉ X.509, chữ ký và định danh GitHub Actions runner.
  - Lưu trữ artifact gói phát hành kèm chữ ký (`.sig`, `.pem`, `.sha256`).

### 3. Workflow: SLSA Level 3 Provenance Generator (`slsa-provenance.yml`)
- **Bộ kích hoạt**: Push `main`, tags `v*`, `workflow_dispatch`.
- **Hành động**:
  - Job `build`: Phân quyền `contents: read`, đóng gói `release.tar.gz`, tính toán SHA-256 base64 checksum của artifact.
  - Job `provenance`: Tái sử dụng workflow tiêu chuẩn `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0` với quyền `id-token: write`, `actions: read`, `contents: write` độc lập hoàn toàn với job build để sinh tệp chứng thực provenance dạng `.intoto.jsonl`.
