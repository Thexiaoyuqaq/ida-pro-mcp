import os
import sys
import time
import json
import asyncio
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from ida_pro_mcp import discovery  # noqa: E402


class _FakeIDAHandler(BaseHTTPRequestHandler):
    server_version = "FakeIDA/1.0"
    delay = 0.0

    def log_message(self, *args):
        pass  # silence

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        req = json.loads(body.decode("utf-8"))
        if self.delay:
            time.sleep(self.delay)
        result = {"method": req.get("method"), "params": req.get("params"), "port": self.server.server_address[1]}
        response = json.dumps({"jsonrpc": "2.0", "result": result, "id": req.get("id")}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def start_fake_instance(registry_id: str, module: str, delay: float = 0.0) -> tuple:
    """Start a fake IDA JSON-RPC server, register it, return (httpd, thread, info)."""
    handler = type("H", (_FakeIDAHandler,), {"delay": delay})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = httpd.server_address[1]
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    info = discovery.InstanceInfo(
        id=registry_id, host="127.0.0.1", port=port, idb_path=f"/tmp/{module}",
        module=module, pid=os.getpid(), kind="gui",
        started_at=time.time(), heartbeat=time.time(),
    )
    discovery.register(info)
    return httpd, thread, info


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        raise AssertionError(name)


async def run_async_checks(server):
    # forward reaches the right instance
    instances = discovery.discover()
    r0 = await server.forward(instances[0], "get_metadata", [])
    check("forward returns result from correct port", r0["port"] == instances[0].port)

    # concurrency: two 0.5s calls to different instances finish in ~0.5s, not ~1s
    a, b = instances[0], instances[1]
    t0 = time.time()
    results = await asyncio.gather(
        server.forward(a, "m", []),
        server.forward(b, "m", []),
    )
    elapsed = time.time() - t0
    check("cross-instance calls run concurrently (<0.9s)", elapsed < 0.9)
    check("both concurrent calls hit distinct ports",
          {results[0]["port"], results[1]["port"]} == {a.port, b.port})


def main():
    tmp = tempfile.mkdtemp(prefix="ida-mcp-test-")
    discovery.REGISTRY_DIR = tmp

    import ida_pro_mcp.server as server  # import after REGISTRY_DIR patch is irrelevant (read at call time)

    servers = []
    try:
        # --- single instance: resolve without explicit database ---
        servers.append(start_fake_instance("aaa111", "alpha.exe"))
        check("discover finds 1 instance", len(discovery.discover()) == 1)
        t = server.resolve_target("")
        check("single instance auto-selected", t.id == "aaa111")

        # --- second instance with a slow response for concurrency test ---
        servers.append(start_fake_instance("bbb222", "beta.dll", delay=0.5))
        # make the first slow too so gather timing is meaningful
        servers[0][0].RequestHandlerClass.delay = 0.5

        check("discover finds 2 instances", len(discovery.discover()) == 2)

        # multiple instances, no selection -> error
        try:
            server.resolve_target("")
            check("ambiguous resolve raises", False)
        except Exception:
            check("ambiguous resolve raises", True)

        # explicit by id / module / port
        check("resolve by id", server.resolve_target("bbb222").id == "bbb222")
        check("resolve by module", server.resolve_target("alpha.exe").id == "aaa111")

        # unknown database -> error
        try:
            server.resolve_target("does-not-exist")
            check("unknown db raises", False)
        except Exception:
            check("unknown db raises", True)

        # active db selection
        server._active_db = "bbb222"
        check("active db used when no arg", server.resolve_target("").id == "bbb222")
        server._active_db = ""

        # async forward + concurrency
        asyncio.run(run_async_checks(server))

        # --- same database opened in two instances -> distinct ids, both live ---
        id_a = discovery.make_id("/tmp/dup.idb", 20001)
        id_b = discovery.make_id("/tmp/dup.idb", 20002)
        check("same path + different port -> different id", id_a != id_b)
        for p, iid in ((20001, id_a), (20002, id_b)):
            discovery.register(discovery.InstanceInfo(
                id=iid, host="127.0.0.1", port=p, idb_path="/tmp/dup.idb", module="dup.exe",
                pid=os.getpid(), kind="gui", started_at=time.time(), heartbeat=time.time()))
        dup_ids = {i.id for i in discovery.discover() if i.idb_path == "/tmp/dup.idb"}
        check("both duplicate-database instances are discoverable", dup_ids == {id_a, id_b})
        check("duplicate instances selectable by port", server.resolve_target("20002").id == id_b)
        discovery.unregister(id_a)
        discovery.unregister(id_b)

        # --- stale/dead pruning: register a dead pid, ensure it's pruned ---
        dead = discovery.InstanceInfo(
            id="dead999", host="127.0.0.1", port=1, idb_path="/tmp/x", module="x",
            pid=0x7FFFFFFE, kind="gui", started_at=time.time(), heartbeat=time.time(),
        )
        discovery.register(dead)
        ids = {i.id for i in discovery.discover()}
        check("dead-pid instance pruned", "dead999" not in ids)

        print("\nALL CHECKS PASSED")
    finally:
        for httpd, _thread, _info in servers:
            httpd.shutdown()


if __name__ == "__main__":
    main()
