# spinxsca — Spinx SecureCode AI

Autonomous AI security code review agent: phân tích mã nguồn, phát hiện lỗ hổng có khả năng khai thác
và hỗ trợ khắc phục dựa trên bằng chứng. Thiết kế và lộ trình nằm trong [docs/](docs/README.md).

**Trạng thái: Phase 4 (nền tảng).** Có ba phần:
- **CLI:** bốn scanner chạy trong sandbox không mạng; code intelligence; incremental scan; vòng đời finding; AI explain, standard và fix (Claude hoặc model nội bộ qua API tương thích OpenAI, có `ai.data_policy`); KEV/EPSS/NVD; release gate; trạng thái finding theo nhánh.
- **Service:** API, web UI, webhook, tái đánh giá tự động khi KB đổi. Mở rộng bằng worker từ xa (lease, fencing, pool on-prem), trạng thái project lưu trên SQLite hoặc PostgreSQL, điều phối bằng queue nội bộ hoặc Temporal. Triển khai bằng Docker Compose hoặc Helm; KB offline đi qua gói có chữ ký.
- **VS Code extension.**

Kết quả và điểm còn thiếu: [Phase 1](docs/roadmap/phase-1-ket-qua.md), [Phase 2](docs/roadmap/phase-2-ket-qua.md), [Phase 3](docs/roadmap/phase-3-ket-qua.md), [Phase 4](docs/roadmap/phase-4-ket-qua.md).

## Yêu cầu

- Node.js ≥ 22.12 (khuyến nghị 24, xem `.nvmrc`), pnpm 11 (`corepack enable`)
- Docker (Docker Desktop hoặc Engine). Scanner chạy trong container không mạng, không capability, rootfs chỉ đọc, user không phải root.
- AI (tuỳ chọn): `ANTHROPIC_API_KEY` hoặc `ant auth login`. Mặc định AI tắt.

## Bắt đầu nhanh

```bash
pnpm install
pnpm images:pull                                     # 4 image scanner ghim digest (~2.3 GB)
pnpm spinxsca info                                   # phiên bản, digest, knowledge base, kiểm tra sandbox
pnpm spinxsca kb sync <path>                         # advisory OSV cho package của dự án (hoặc --ecosystem npm)
pnpm spinxsca scan <path>                            # quét, đối chiếu baseline, ghi báo cáo
pnpm spinxsca findings list <path>
pnpm spinxsca findings show SPX-000001 <path>
pnpm eval                                            # 12 ca, KB fixture, không gọi mạng
```

State của dự án nằm ở `<path>/.spinxsca/` (SQLite + artifact content-addressed). Báo cáo nằm ở `.spinxsca/reports/<scanId>/`. Knowledge base dùng chung nằm ở `~/.spinxsca/kb`.

| Lệnh | Việc |
|---|---|
| `scan --mode dependency-reassessment` | Chỉ chạy lại SCA với snapshot knowledge base mới; advisory mới mang nguyên nhân `NEW_ADVISORY` |
| `scan --ai explain` | Model kiểm chứng và giải thích finding mã nguồn mới (gửi đoạn mã đã che secret), có ngân sách `--max-cost` |
| `scan --fail-on high [--all-findings]` | Mã thoát 1 khi có finding ≥ mức; finding đã disposition hoặc AI kết luận `UNLIKELY` không chặn |
| `scan --diff origin/main` | Incremental: chỉ quét phần thay đổi và các endpoint/caller bị ảnh hưởng; finding ngoài phạm vi được carry forward |
| `scan --ai standard` | Thêm planner, investigators theo packet và auditor độc lập; finding AI hợp nhất với finding scanner |
| `scan --baseline branch:main` | Đối chiếu với baseline của nhánh (`baseline set --branch main --reason …`) |
| `findings dispose <id> --as false-positive\|accepted-risk\|wont-fix\|duplicate --reason …` | Quyết định của con người, có người quyết định và hạn (accepted risk bắt buộc `--expires`) |
| `compare <scanA> <scanB>` | Delta và lý do từng thay đổi (code, dependency, advisory, rule, scanner, coverage) |
| `explain <id>` / `ask "<câu hỏi>"` | AI cho một finding / câu hỏi về mã nguồn |
| `gate --branch main` | Release gate: scan FULL gần nhất ≤ 72 giờ, coverage đủ, không còn finding mở ≥ high hoặc nằm trong KEV (cấu hình ở mục `gate`) |
| `branches` / `status` | Trạng thái finding theo nhánh (open / fixed / not re-evaluated) |
| `kb sync --intel kev,epss,nvd` | Thêm CISA KEV, FIRST EPSS, NVD CVSS vào KB; finding phụ thuộc hiển thị cả ba |
| `serve --data-dir <dir>` | Service: API `/v1`, UI `/ui`, webhook, worker, sync KB định kỳ (`server init` tạo token admin); `--orchestrator temporal`; `SPINXSCA_DATABASE_URL` cho Postgres |
| `worker register` / `worker run` | Worker từ xa chạy quét cạnh mã nguồn, ghi kết quả qua control plane (`server provision-worker` phát token) |
| `kb bundle keygen\|export\|import` | Gói KB có chữ ký cho môi trường on-prem / không mạng |
| `fix <id>` / `verify-fix <id>` | Patch do AI đề xuất, áp dụng vào bản sao, re-scan và chạy test trong sandbox; `--apply --patch <id>` mới ghi vào working tree |
| `export --format sarif\|json\|md\|csv\|cyclonedx\|pr-comment`, `sbom` | Xuất kết quả |
| `kb sync\|status\|snapshots\|lookup\|import\|export` | Quản lý knowledge base OSV |

Mã thoát: `0` đạt, `1` vi phạm policy, `2` lỗi thực thi, `3` coverage chưa đầy đủ khi được yêu cầu.

## Cấu trúc

```text
packages/schemas    Zod schema cho mọi artifact (+ xuất JSON Schema)
packages/core       domain, ports, Activity, fingerprint, reconciliation, nguyên nhân thay đổi, runScan, compare, lifecycle
packages/storage    SQLite (Drizzle) system of record + artifact store content-addressed
packages/temporal   Temporal workflow/activity cho job, dispatcher, worker
packages/server     service: Hono API, web UI, webhooks, job queue/worker, KB reassessment, notifications
packages/code-intel tree-sitter extractors (JS/TS, Python, Java), symbol/call graph, endpoint & auth map, change impact
packages/kb         knowledge base OSV: revision bất biến, snapshot, coverage, sync, đóng gói DB cho osv-scanner
packages/workspace  SourceTree cục bộ (git/fs) cho snapshot
packages/sandbox    Docker runner cứng hoá + preflight, RepositoryConfinement
packages/scanners   adapter Semgrep, osv-scanner (+ SBOM), Gitleaks, Trivy; image ghim digest
packages/reporting  SARIF 2.1.0, Markdown, JSON, CSV
packages/agent      LlmProvider (Claude), vòng lặp agent, tool đọc mã và graph, explain/ask/planner/investigator/auditor/remediation
apps/cli            spinxsca CLI và eval harness
apps/vscode         VS Code extension (CLI cục bộ hoặc server)
apps/action         GitHub Action composite (incremental scan, SARIF, PR comment, policy gate)
ci/                 template GitLab CI
deploy/             Dockerfile, docker-compose, Helm chart (control plane + worker)
prompts/            prompt bundle (digest ghi vào manifest)
rules/semgrep       rule bundle spinxsca-core (6 rule, kèm test `semgrep --test`)
evals/              ca kiểm thử có ground truth, KB fixture OSV, ngưỡng nghiệm thu
```

## Phát triển

```bash
pnpm check        # lint + typecheck + test (test Docker tự bỏ qua nếu thiếu image)
pnpm rules:test   # semgrep --test cho rule bundle
pnpm build        # bundle CLI vào apps/cli/dist (kèm rule và prompt)
pnpm db:generate  # sinh migration sau khi sửa packages/storage/src/schema.ts
pnpm images:pin   # cập nhật digest image scanner
```

Test gọi Claude API thật chỉ chạy khi đặt `SPINXSCA_LIVE_TESTS=1`. Xem [CONTRIBUTING.md](CONTRIBUTING.md).
