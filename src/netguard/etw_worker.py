"""Tiến trình con: mở phiên ETW cho Kernel-Network và in sự kiện ra stdout (JSON từng dòng).
Tự thoát (và dừng phiên ETW) khi tiến trình cha đóng stdin hoặc kết thúc."""
from __future__ import annotations

import argparse
import json
import sys


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-kernel-filter", action="store_true")
    ap.add_argument("--no-event-filter", action="store_true")
    args = ap.parse_args(argv)

    from .realtime import KERNEL_NETWORK_GUID, SESSION_NAME, WANTED, parse_event

    try:
        import ctypes as ct

        import etw
        from etw import evntprov as ep
        from etw.etw import ProviderParameters
    except ImportError as exc:
        emit({"status": "error", "kind": "missing-lib", "msg": f"Thiếu thư viện pywintrace: {exc}"})
        return 3

    bad = {"n": 0}

    def on_event(item) -> None:
        try:
            event_id, data = item
            rec = parse_event(event_id, data)
            if rec:
                emit(rec)
            elif event_id in WANTED:
                bad["n"] += 1
                if bad["n"] <= 3:  # báo tên trường để chẩn đoán nếu định dạng khác dự kiến
                    emit({"id": int(event_id), "bad": 1, "keys": sorted(map(str, data))[:20]})
            else:
                emit({"id": int(event_id)})
        except Exception:
            pass

    keep: list = []
    params = None
    kernel_filter = False
    if not args.no_kernel_filter:
        try:  # chỉ nhận đúng các mã sự kiện cần thiết ngay từ phía kernel
            ids = ep.EVENT_FILTER_EVENT_ID(True, list(WANTED))
            size = ct.sizeof(ep.EVENT_FILTER_EVENT_ID) + ct.sizeof(ct.c_ushort) * len(WANTED)
            desc = ep.EVENT_FILTER_DESCRIPTOR(ct.addressof(ids.get().contents), size, ep.EVENT_FILTER_TYPE_EVENT_ID)
            pp = ProviderParameters(0, [desc])
            params = pp.get()
            keep += [ids, desc, pp]  # giữ tham chiếu để vùng nhớ không bị giải phóng
            kernel_filter = True
        except Exception as exc:
            emit({"status": "warn", "msg": f"Không dựng được bộ lọc kernel: {exc!r}"})

    provider = etw.ProviderInfo("Microsoft-Windows-Kernel-Network", etw.GUID(KERNEL_NETWORK_GUID), params=params)
    job = etw.ETW(session_name=SESSION_NAME, providers=[provider], event_callback=on_event,
                  event_id_filters=None if args.no_event_filter else list(WANTED))
    try:
        job.start()
    except OSError as exc:
        emit({"status": "error", "code": getattr(exc, "winerror", None), "msg": str(exc)})
        return 4
    except Exception as exc:
        emit({"status": "error", "code": None, "msg": repr(exc)})
        return 4

    emit({"status": "ready", "kernel_filter": kernel_filter})
    try:
        sys.stdin.read()  # chặn tới khi cha đóng pipe / bị kết thúc
    except Exception:
        pass
    finally:
        try:
            job.stop()
        except Exception:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
