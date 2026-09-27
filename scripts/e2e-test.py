# -*- coding: utf-8 -*-
"""p2p 数据面端到端测试

在同一条打洞出来的 UDP 路径上验证：
  1. --share / --forward 能建立 QUIC 数据面
  2. echo 数据能穿过双向通道
  3. 大 payload 完整性
  4. 多并发连接
  5. token 不一致时必须握不上手

用法（先编译好 p2p 二进制）：
    go build -o p2p.exe .
    python scripts/e2e-test.py

可用环境变量 P2P_BIN 指定二进制的绝对路径。
"""
import os
import socket
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXE = os.environ.get("P2P_BIN") or os.path.join(
    ROOT, "p2p.exe" if os.name == "nt" else "p2p")

ECHO_PORT = 18080
A_PORT = 45690
B_PORT = 45691
LOCAL_FWD = 19090
TOKEN = "e2e-test-token-abc123"

B2_PORT = 45692
LOCAL_FWD2 = 19091

procs = []
results = []


def log(m):
    print(m, flush=True)


# ---------------- echo 服务 ----------------
def echo_loop(srv):
    while True:
        try:
            c, _ = srv.accept()
        except OSError:
            return
        threading.Thread(target=echo_conn, args=(c,), daemon=True).start()


def echo_conn(c):
    try:
        while True:
            d = c.recv(65536)
            if not d:
                break
            c.sendall(d)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass


def start_echo():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", ECHO_PORT))
    srv.listen(32)
    threading.Thread(target=echo_loop, args=(srv,), daemon=True).start()
    return srv


# ---------------- p2p 进程 ----------------
def start_p2p(name, args):
    log("[启动] %s: p2p %s" % (name, " ".join(args)))
    p = subprocess.Popen(
        [EXE] + args,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        encoding="utf-8", errors="replace", cwd=ROOT,
    )
    procs.append((name, p))
    return p


def wait_port(port, timeout):
    end = time.time() + timeout
    while time.time() < end:
        try:
            s = socket.create_connection(("127.0.0.1", port), 1.0)
            s.close()
            return True
        except OSError:
            time.sleep(0.3)
    return False


def kill_all():
    for _, p in procs:
        try:
            p.terminate()
        except Exception:
            pass
    for name, p in procs:
        try:
            out, _ = p.communicate(timeout=5)
        except Exception:
            try:
                p.kill()
                out, _ = p.communicate(timeout=5)
            except Exception:
                out = ""
        tail = [l for l in (out or "").splitlines() if l.strip()][-12:]
        if tail:
            log("---- %s 输出（末尾）----" % name)
            for l in tail:
                log("    " + l)


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    log("  [%s] %s%s" % ("通过" if ok else "失败", name, ("  " + detail) if detail else ""))


def roundtrip(payload, timeout=20):
    s = socket.create_connection(("127.0.0.1", LOCAL_FWD), timeout)
    s.settimeout(timeout)
    s.sendall(payload)
    got = b""
    while len(got) < len(payload):
        d = s.recv(65536)
        if not d:
            break
        got += d
    s.close()
    return got


def main():
    if not os.path.exists(EXE):
        log("找不到二进制 %s，请先 go build" % EXE)
        return 1

    start_echo()
    log("[ok] echo 服务已监听 127.0.0.1:%d" % ECHO_PORT)

    # A = 开放端口的一侧（--share），B = 访问的一侧（--forward）
    start_p2p("A-advertise-share",
              ["advertise", "--port", str(A_PORT),
               "--share", str(ECHO_PORT), "--token", TOKEN])
    time.sleep(3)
    # 对端地址直接写 127.0.0.1:A_PORT，绕开 NAT，专注验证数据面
    start_p2p("B-connect-forward",
              ["connect", "127.0.0.1:%d" % A_PORT, "--port", str(B_PORT),
               "--forward", "%d:%d" % (LOCAL_FWD, ECHO_PORT), "--token", TOKEN])

    log("")
    log("=== 测试 1/4: 数据面是否建立 ===")
    up = wait_port(LOCAL_FWD, 90)
    check("本地转发端口 %d 已监听" % LOCAL_FWD, up)
    if not up:
        return 1
    time.sleep(2)  # 等 QUIC 握手完成

    log("")
    log("=== 测试 2/4: 小包 echo ===")
    try:
        got = roundtrip(b"hello-p2p-data-plane")
        check("小包往返", got == b"hello-p2p-data-plane", "收到 %r" % got[:60])
    except Exception as e:
        check("小包往返", False, repr(e))

    log("")
    log("=== 测试 3/4: 1MB payload 完整性 ===")
    try:
        payload = os.urandom(1024 * 1024)
        t0 = time.time()
        got = roundtrip(payload, timeout=60)
        dt = time.time() - t0
        speed = (len(got) * 2 / dt / 1024 / 1024) if dt > 0 else 0
        check("1MB 逐字节一致", got == payload,
              "收回 %d 字节, 往返 %.2fs, 约 %.1f MB/s" % (len(got), dt, speed))
    except Exception as e:
        check("1MB 逐字节一致", False, repr(e))

    log("")
    log("=== 测试 4/4: 8 条并发连接 ===")
    try:
        errs = []

        def worker(i):
            try:
                msg = ("conn-%d-" % i).encode() * 40
                got = roundtrip(msg)
                if got != msg:
                    errs.append("conn %d 数据不一致 (%d/%d)" % (i, len(got), len(msg)))
            except Exception as e:
                errs.append("conn %d: %r" % (i, e))

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(60)
        check("8 条并发连接", not errs, "; ".join(errs[:3]))
    except Exception as e:
        check("8 条并发连接", False, repr(e))

    log("")
    log("=== 附加: token 不一致必须握不上手 ===")
    try:
        start_p2p("B2-wrong-token",
                  ["connect", "127.0.0.1:%d" % A_PORT, "--port", str(B2_PORT),
                   "--forward", "%d:%d" % (LOCAL_FWD2, ECHO_PORT),
                   "--token", "WRONG-TOKEN-xxxx"])
        ok_listen = wait_port(LOCAL_FWD2, 60)
        bad = False
        if ok_listen:
            time.sleep(3)
            try:
                s = socket.create_connection(("127.0.0.1", LOCAL_FWD2), 8)
                s.settimeout(8)
                s.sendall(b"should-not-arrive")
                try:
                    bad = len(s.recv(4096)) > 0
                except socket.timeout:
                    bad = False
                s.close()
            except Exception:
                bad = False
        check("token 不匹配时数据无法穿过", ok_listen and not bad,
              "本地端口已开=%s 数据穿过=%s" % (ok_listen, bad))
    except Exception as e:
        check("token 不匹配时数据无法穿过", False, repr(e))

    return 0


if __name__ == "__main__":
    code = 1
    try:
        code = main()
    finally:
        log("")
        log("================ 汇总 ================")
        for name, ok, detail in results:
            log("  %s  %s %s" % ("PASS" if ok else "FAIL", name, detail))
        passed = sum(1 for _, ok, _ in results if ok)
        log("  %d/%d 通过" % (passed, len(results)))
        log("")
        kill_all()
    sys.exit(code)
