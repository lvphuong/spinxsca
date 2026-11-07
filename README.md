# spinxsca — Spinx SecureCode AI

Autonomous AI security code review agent: phân tích mã nguồn, phát hiện lỗ hổng có khả năng khai thác
và hỗ trợ khắc phục dựa trên bằng chứng. Thiết kế và lộ trình nằm trong [docs/](docs/README.md).

**Trạng thái: Phase 5 (rà soát tự chủ có quản trị).** Có bốn phần:
- **CLI:** bốn scanner chạy trong sandbox không mạng; code intelligence; incremental scan; vòng đời finding; AI explain, standard và fix (Claude hoặc model nội bộ qua API tương thích OpenAI, có `ai.data_policy`); KEV/EPSS/NVD; release gate; trạng thái finding theo nhánh.
- **Service:** API, web UI, webhook, tái đánh giá tự động khi KB đổi. Mở rộng bằng worker từ xa (lease, fencing, pool on-prem), trạng thái project lưu trên SQLite hoặc PostgreSQL, điều phối bằng queue nội bộ hoặc Temporal. Triển khai bằng Docker Compose hoặc Helm; KB offline đi qua gói có chữ ký.
- **Rà soát tự chủ (`spinxsca review`, `scan --ai deep`):** một "case" có lead, các persona chuyên trách (validator, dependency, secrets, iac, appsec, exploit, fixer, verifier) làm việc qua tool có kiểu; mọi tool call đi qua policy engine L0–L12 (hard floor, human-only, grant, reviewer model), audit và journal có hash-chain, inbox bền vững cho lần chạy không người trực; PoC L3 trong sandbox không mạng với oracle do host quyết định; sửa lỗi lặp có verifier độc lập và chỉ áp vào repo khi con người duyệt.
- **VS Code extension** và **desktop app** (`apps/desktop`, Tauri 2, chưa ký).

- **Model cục bộ và repo lớn (Phase 7):** `ai.models`/`ai.routing` định tuyến vai sang Claude, endpoint OpenAI-compatible (vLLM, LM Studio) hoặc Ollama; `spinxsca ai doctor` đo endpoint và in cấu hình; mọi session tính compaction và `max_tokens` từ context window; repo hàng trăm nghìn dòng được chia shard tất định, điều tra song song (`scan --shards`), tái dùng shard không đổi và gộp bằng reducer chỉ nhìn claim.

Kết quả và điểm còn thiếu: [Phase 1](docs/roadmap/phase-1-ket-qua.md), [Phase 2](docs/roadmap/phase-2-ket-qua.md), [Phase 3](docs/roadmap/phase-3-ket-qua.md), [Phase 4](docs/roadmap/phase-4-ket-qua.md), [Phase 5](docs/roadmap/phase-5-ket-qua.md), [Phase 6](docs/roadmap/phase-6-ket-qua.md), [Phase 7](docs/roadmap/phase-7-ket-qua.md).

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
| `scan --fail-on high [--all-findings]` | Mã thoát 1 khi có finding ≥ mức; finding đã disposition không chặn. AI hạ severity hoặc kết luận `UNLIKELY` chỉ được tính khi `gate.trust_ai_downgrades: true` (mặc định gate dùng max(scanner, AI)) |
| `scan --diff origin/main` | Incremental: chỉ quét phần thay đổi và các endpoint/caller bị ảnh hưởng; finding ngoài phạm vi được carry forward |
| `scan --ai standard [--context-pack ctx.yaml]` | Recon trích ground truth (invariant, baseline-correct reference, variant family, carve-out) trước khi săn; investigator theo packet phải trả checklist PASS/FAIL/UNKNOWN và hunt log; critic rà sót; auditor độc lập; finding AI hợp nhất với finding scanner và chỉ chặn gate khi CONFIRMED (`gate.ai_discovered_min_classification`) |
| `scan --ai deep` | Case tự chủ không người trực (như `review --unattended`): item RECON → LOGIC_AUDIT theo nhóm resource bị census đánh dấu → critic → validator kiểu downgrade-don't-delete |
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
| `review [--mode observe\|supervised\|autonomous] [--goal …] [--objectives …] [--l3] [--fix] [--unattended]` | Quét + case tự chủ: triage mọi finding có bằng chứng, VEX/reachability cho dependency, săn lỗ hổng mà scanner bỏ sót, PoC trong sandbox, sửa lỗi có verifier; báo cáo case ở `reports/<scanId>/case.md` |
| `case list` / `case show <caseId> [--journal] [--audit] [--verify-chain]` | Xem case: objectives, coverage, verdict, journal và audit (kiểm hash-chain) |
| `inbox list\|show\|approve\|deny [--grant once\|case\|standing] [--server URL --project ID]` | Hành động đang chờ con người (người trả lời đầu tiên thắng; yêu cầu human-only chỉ duyệt một lần) |
| `inbox answer <id> --answer … --provenance …` | Trả lời câu hỏi rà soát mà recon không tự quyết được (vai trò, tenant, triển khai, quy tắc nghiệp vụ); câu trả lời thành memory `claimed`, verdict phụ thuộc được re-triage |
| `memory list\|add\|promote\|forget` | Bộ nhớ dự án dùng cho các case sau (bài học do agent đề xuất chờ con người duyệt) |
| `fix <id> --iterate [n]` | Lặp đề xuất patch với phản hồi re-scan/test đến khi verified |
| `eval --suite governance` / `eval --suite ai --ai-provider scripted` | Ma trận quyết định policy (178 dòng) / cổng cứng của rà soát tự chủ (không false-confirm, không lộ secret, không side effect) |
| `eval --suite logic --ai standard [--ai-provider anthropic]` | Suite logic/authorization (IDOR sibling, tenant isolation, race, mass assignment, workflow bypass, fail-open, negative control); đo thêm sibling-sweep recall và invariant coverage; case `live_only` chỉ tính với model thật |
| `eval --suite scale --ai standard [--ai-provider scripted\|scripted-weak]` | Repo tổng hợp sinh bằng script (300 file trong CI, `scripts/gen-scale-fixture.ts` cho 300k dòng); đo recall lỗi gieo, số shard, thời gian, RSS của điều tra theo shard |
| `ai doctor --provider ollama\|openai-compatible --model <id> [--base-url]` | Đo endpoint model cục bộ (context window, tool call native/prompted, JSON, tok/s) và in `ai.models`/`ai.routing` khuyến nghị |
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
