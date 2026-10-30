# Đóng góp cho spinxsca

## Nguyên tắc kiến trúc phải giữ

Các quyết định nằm trong [docs/adr](docs/adr/README.md). Những điểm review sẽ kiểm tra:

- `packages/core` không import adapter (ADR-017). Side effect mới đi qua một port trong `packages/core/src/ports.ts`.
- Model không sở hữu artifact chuẩn: ID, fingerprint, báo cáo do host sinh (ADR-022).
- Không đánh dấu finding là đã sửa nếu coverage không chứng minh được (ADR-006).
- Scanner chạy trong container ghim digest với profile do host chọn; không thêm tuỳ chọn cho repo hoặc model nới sandbox (ADR-021, ADR-025).
- Thay đổi schema lưu trữ phải kèm migration (`pnpm db:generate`), không sửa migration đã phát hành.

## Quy trình PR

1. `pnpm check` phải xanh.
2. Thay đổi `rules/`, taxonomy, fingerprint, reconciliation hoặc prompt phải kèm kết quả `pnpm eval` trong mô tả PR (ADR-027). Không hạ ngưỡng trong `evals/*/thresholds.yaml` để PR qua.
3. Rule mới cần file test cạnh rule với chú thích `ruleid:` / `ok:` và `pnpm rules:test` phải pass.
4. Ca eval mới cần cả trường hợp dương và vùng âm (`negatives`), ghi `min_phase` cho finding mà phase hiện tại chưa phát hiện được.
5. Quyết định kiến trúc mới hoặc thay đổi: thêm/sửa ADR và cập nhật `docs/adr/README.md`.

## Quy ước

- Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
- TypeScript strict, Biome để format/lint (`pnpm lint:fix`).
- Tài liệu thiết kế viết tiếng Việt; tên định danh, thông điệp CLI và báo cáo viết tiếng Anh.
- Không commit `.spinxsca/`, `evals/results/` hoặc secret. Test gọi API thật chỉ chạy với `SPINXSCA_LIVE_TESTS=1`.
