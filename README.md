# NetGuard

![Platform](https://img.shields.io/badge/Platform-Windows%2011-blue?logo=windows)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python)
![Framework](https://img.shields.io/badge/GUI-PySide6%20%2F%20Qt-brightgreen?logo=qt)
![Package Manager](https://img.shields.io/badge/Packaged%20with-uv-purple)

Ứng dụng PySide6 giám sát toàn bộ kết nối mạng vào/ra trên Windows 11 theo thời gian thực (ETW), tự động phân loại mức rủi ro theo heuristic & threat feeds, tự chặn mối nguy qua Windows Firewall và ghi lại toàn bộ nhật ký thay đổi để dễ dàng hoàn tác hoặc khôi phục.

---

## Tính năng nổi bật

- ⚡ **Giám sát thời gian thực bằng ETW (Event Tracing for Windows)**: Nhận biết sự kiện kết nối TCP/UDP ngay lập tức từ kernel provider `Microsoft-Windows-Kernel-Network`, bắt trọn cả các kết nối ngắn mà phương pháp polling định kỳ có thể bỏ sót.
- 🛡️ **Tự động phân tích & chấm điểm rủi ro**: Đánh giá dựa trên Feodo Tracker, Emerging Threats, cổng backdoor/C2/Tor/mining, tên file giả mạo, chữ ký số không hợp lệ, script engine (PowerShell, mshta, certutil,...) kết nối ngoại vi.
- 🚫 **Tự động chặn thông minh qua Windows Firewall**: Tự tạo rule chặn IP nguy hại hoặc app lạ trong user directory; tích hợp cơ chế cầu dao an toàn (Circuit Breaker) chống chặn nhầm hàng loạt.
- 🔄 **An toàn & Khôi phục tuyệt đối**: Ghi nhận toàn bộ thay đổi (Undo từng mục), tự động sao lưu cấu hình ra JSON, đối soát Firewall lúc khởi động và hỗ trợ sao lưu chính sách gốc (`.wfw`).
- 💻 **Giao diện hiện đại & Khởi chạy êm ái**: Thiết kế giao diện Qt/PySide6 trực quan, hỗ trợ khởi chạy ngầm hoàn toàn không nhấp nháy cửa sổ console đen qua VBScript/Shortcut UAC.

---

## Khởi chạy nhanh & Tạo Shortcut

- **Tạo Shortcut Desktop**:
  - Chạy `create_shortcut.cmd` hoặc `run.cmd --shortcut` để tạo shortcut NetGuard với icon khiên bảo vệ ngoài Desktop (tự xin quyền UAC và khởi chạy giao diện không hiện console).
- **run.vbs**: Nhấp đúp hoặc chạy `wscript run.vbs` để mở NetGuard ngầm (ẩn hoàn toàn cửa sổ CMD).
- **run.cmd**: Script điều khiển đa năng:
  - `run.cmd` : Mở giao diện NetGuard.
  - `run.cmd --admin` (hoặc `-a`) : Mở với quyền Administrator (yêu cầu UAC).
  - `run.cmd --console` (hoặc `-c`) : Mở kèm console để theo dõi log thời gian thực.
  - `run.cmd --vbs` (hoặc `-s`) : Mở qua VBScript (ẩn console).
  - `run.cmd --shortcut` : Tạo shortcut ra Desktop.
  - `run.cmd --etw-test` : Chạy kiểm tra chẩn đoán hệ thống ETW.

---

## Cài đặt & Chạy qua CLI (`uv`)

Dự án được tối ưu quản lý gói qua [`uv`](https://github.com/astral-sh/uv):

```powershell
# Cài đặt môi trường & dependencies
uv sync

# Chạy NetGuard (chế độ giám sát thông thường)
uv run netguard

# Chạy thử nghiệm an toàn (dry-run, không can thiệp Windows Firewall)
uv run netguard --dry-run

# Chạy toàn bộ test suite
uv run pytest
```

> [!NOTE]
> Để NetGuard thực thi được chức năng **Tự động chặn** hoặc **Thêm quy tắc Firewall**, ứng dụng cần quyền **Administrator**:
> - Bấm nút *Chạy lại với quyền Administrator* trong tab **Tổng quan** (sẽ hiện hộp thoại UAC xác nhận).
> - Hoặc mở terminal bằng *Run as administrator* rồi chạy `uv run netguard`.
> - Hoặc chạy `run.cmd --admin`.

---

## Giám sát thời gian thực (ETW)

Ngoài chu kỳ quét định kỳ, NetGuard nhận sự kiện **ngay khi kết nối được mở** từ kernel provider `Microsoft-Windows-Kernel-Network` (TCP kết nối/thiết lập, UDP gửi). Sự kiện được phân loại và tự chặn tức thì; các kết nối chớp nhoáng vẫn được lưu hiển thị trên giao diện thêm 15 giây.

- **Tiến trình độc lập**: Worker ETW chạy trong một tiến trình con riêng biệt (`netguard.etw_worker`). Nếu worker gặp sự cố hoặc CPU cao bất thường (>35% liên tục ~9s), app sẽ tự ngắt worker để bảo vệ hiệu năng hệ thống mà không ảnh hưởng app chính.
- **Tối ưu hiệu năng**: Chỉ lắng nghe các mã sự kiện kết nối cần thiết, bỏ qua gói dữ liệu payload thông thường.
- **Tên phiên ETW**: Mang tên `NetGuard-ETW`. Tự động dọn dẹp khi app tắt hoặc khởi động lại. Dọn thủ công nếu cần: `logman stop NetGuard-ETW -ets`.
- **Chẩn đoán ETW**: Chạy lệnh `uv run netguard --etw-test` từ terminal Administrator để kiểm tra bộ lọc kernel, event IDs nhận được và byte order của port.

---

## Phân loại rủi ro

| Mức độ | Điều kiện & Ý nghĩa |
|---|---|
| **Nội bộ** | Kết nối mạng LAN cục bộ / loopback (`127.0.0.1`, `::1`, subnet riêng) |
| **Tin cậy** | Ứng dụng nằm trong danh sách tin cậy (whitelist), hoặc chương trình hệ thống/nhà phát triển uy tín có chữ ký số hợp lệ |
| **Bình thường** | Điểm nguy cơ < 30 |
| **Đáng ngờ** | 30 ≤ Điểm nguy cơ < Ngưỡng cảnh báo (mặc định 70) |
| **Nguy hiểm** | Điểm nguy cơ ≥ Ngưỡng cảnh báo (mặc định 70) |

**Cơ chế tính điểm**:
- IP nằm trong danh bạ đe dọa (Feodo, ET): `+90`
- Cổng kết nối nguy cơ cao (C2, Botnet, Tor, Cryptomining): `+40` ~ `+60`
- Tên tệp ngụy trang đuôi kép (vd: `document.pdf.exe`): `+60`
- Thực thi từ vị trí bất thường (`Temp`, `Downloads`, `Public`,...): `+30` ~ `+50`
- Không có chữ ký số hoặc chữ ký bị thu hồi / không hợp lệ: `+20` ~ `+40`
- Script engines (`powershell.exe`, `mshta.exe`, `certutil.exe`,...) tạo kết nối ra ngoài: `+40`
- Quá nhiều kết nối đồng thời từ một tiến trình lạ: `+30`

---

## Quy tắc chặn & Cầu dao an toàn

- **Chặn theo IP**: Áp dụng khi có bằng chứng rõ ràng về địa chỉ đích độc hại (chặn cả chiều Inbound & Outbound).
- **Chặn theo Chương trình**: Áp dụng khi mối nguy gắn liền với ứng dụng (nằm trong thư mục người dùng).
- **Danh sách loại trừ bất khả xâm phạm**: Không bao giờ chặn IP loopback/LAN, DNS public uy tín (Cloudflare, Google), tiến trình core Windows (`C:\Windows\System32`), hoặc các mục nằm trong danh sách trắng do người dùng thêm vào.
- **Cầu dao an toàn (Circuit Breaker)**: Nếu hệ thống kích hoạt tự động chặn vượt quá 8 mục trong 1 phút, chế độ tự chặn sẽ tạm ngừng 5 phút và gửi cảnh báo để tránh chặn nhầm dây chuyền.

---

## Sao lưu, Đối soát & Khôi phục

| Cơ chế | Tác dụng |
|---|---|
| **Nhật ký thay đổi (Audit Log)** | Ghi lại toàn bộ hành động: Chặn, Bỏ chặn, Đổi cài đặt, Thêm tin cậy. Bấm chọn bất kỳ mục nào để **Hoàn tác (Undo)** ngay tức thì. |
| **Bản sao lưu JSON** | Tự động tạo snapshot lúc mở ứng dụng, trước khi thực hiện thay đổi đầu tiên hoặc trước khi phục hồi. Có thể xuất/nhập bản sao lưu thủ công. |
| **Đối soát Firewall** | Tự động kiểm tra trạng thái quy tắc NetGuard trên Windows Firewall lúc khởi động; tự thêm lại rule bị thiếu và phát hiện rule không đồng nhất. |
| **Chính sách gốc (`.wfw`)** | Xuất chính sách Firewall gốc ra `backups\firewall-original.wfw` ngay lần đầu chạy với quyền Admin, làm phương án an toàn tuyệt đối. |
| **Gỡ bỏ khẩn cấp** | Một cú click chuột trong tab Cài đặt để xóa toàn bộ các rule do NetGuard tạo ra và đưa hệ thống mạng về nguyên trạng. |

Dữ liệu cục bộ được lưu trữ tại `%LOCALAPPDATA%\NetGuard\` (file cấu hình, nhật ký `netguard.log`, cơ sở dữ liệu `netguard.db`).

---

## Cấu trúc thư mục

```text
netguard/
├── assets/                  # Tài nguyên ứng dụng (icon khiên, logo)
├── src/
│   └── netguard/
│       ├── __init__.py
│       ├── __main__.py      # Điểm khởi chạy ứng dụng
│       ├── app.py           # Khởi tạo Qt Application
│       ├── classifier.py    # Bộ máy phân loại & chấm điểm rủi ro
│       ├── config.py        # Quản lý cài đặt & cấu hình
│       ├── engine.py        # Lõi điều phối giám sát & hành động
│       ├── etw_worker.py    # Tiến trình con xử lý sự kiện ETW
│       ├── feed.py          # Tải & đồng bộ danh bạ IP độc hại
│       ├── firewall.py      # Tương tác Windows Firewall (netsh)
│       ├── guard.py         # Giám sát quy tắc bảo vệ & cầu dao
│       ├── models.py        # Cấu trúc dữ liệu & dataclass
│       ├── monitor.py       # Quét kết nối mạng hệ thống (psutil)
│       ├── netutil.py       # Tiện ích mạng & phân giải IP
│       ├── realtime.py      # Quản lý kết nối sự kiện thời gian thực
│       ├── signatures.py    # Kiểm tra chữ ký số tiến trình
│       ├── snapshots.py     # Sao lưu & phục hồi dữ liệu JSON
│       ├── storage.py       # Cơ sở dữ liệu SQLite lưu nhật ký
│       └── ui/              # Giao diện người dùng PySide6
│           ├── main_window.py
│           ├── pages.py
│           ├── theme.py
│           └── widgets.py
├── tests/                   # Bộ kiểm thử đơn vị & tích hợp (pytest)
├── create_shortcut.cmd      # Script tạo shortcut Desktop
├── create_shortcut.ps1      # PowerShell tạo shortcut
├── create_shortcut.vbs      # VBScript hỗ trợ shortcut
├── pyproject.toml           # Cấu hình dự án Python & dependencies
├── run.cmd                  # Script khởi chạy NetGuard
├── run.vbs                  # Script khởi chạy ngầm (không hiện console)
└── uv.lock                  # Lock file quản lý phiên bản thư viện
```

---

## Giấy phép (License)

Dự án được phân phối dưới giấy phép [MIT License](LICENSE).
