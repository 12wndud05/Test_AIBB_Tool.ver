"""
Shell Session - AI 에이전트가 '쉘을 열어' 직접 명령을 실행하는 통로.

DockerShellSession: 격리된 공격자 컨테이너 안에 bash 한 프로세스를 띄워 두고
(stdin 파이프), 명령을 흘려보내며 출력을 받는다. 한 bash 프로세스가 유지되므로
cd/환경변수/백그라운드 작업(리버스쉘 대기 등) 상태가 다음 명령으로 이어진다.

안전: CLAUDE.md의 로컬 격리 원칙. 명령 안의 http(s) 대상 호스트를 best-effort로
검사해 스코프 밖(공인 IP/미허용 도메인)을 차단한다. 근본 격리는 '공격자 컨테이너가
붙은 도커 네트워크' 자체가 담당한다.
"""
import re
import time
import uuid
import queue
import threading
import ipaddress
import subprocess


class DockerShellSession:
    def __init__(self, container, target_alias=None, shell="/bin/bash"):
        self.container = container
        self.allowed = {"127.0.0.1", "localhost", "::1"}
        if target_alias:
            self.allowed.add(target_alias)

        # 바이너리 모드(text=False) — Windows에서 text 모드 파이프가 '\n'을 '\r\n'으로
        # 변환해 bash 명령 끝에 '\r'이 붙어 깨지는 문제를 피한다.
        self.proc = subprocess.Popen(
            ["docker", "exec", "-i", container, shell],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            bufsize=0,
        )
        self._q = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        for raw in self.proc.stdout:
            self._q.put(raw.decode("utf-8", errors="replace"))

    def _host_allowed(self, host):
        if host in self.allowed:
            return True
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback  # 도커 내부망(172.x 등) 허용
        except ValueError:
            return False  # 허용목록에 없는 도메인은 차단

    def _scope_ok(self, command):
        """명령에 등장하는 http(s) 대상 호스트가 스코프 안인지 best-effort 검사."""
        for host in re.findall(r'https?://([^/\s:\'"]+)', command):
            if not self._host_allowed(host):
                return False, host
        return True, None

    def run(self, command, timeout=30):
        """명령을 실행하고 {'output', 'exit_code', 'error'} 반환."""
        ok, bad = self._scope_ok(command)
        if not ok:
            return {"output": "", "exit_code": None,
                    "error": f"blocked: out-of-scope host '{bad}' "
                             f"(allowed: {sorted(self.allowed)} + private IPs)"}

        marker = f"__AIBB_{uuid.uuid4().hex}__"
        try:
            # 명령 실행 후 'MARKER <exit_code>' 한 줄을 찍어 출력 끝을 표시.
            # 바이너리로 인코딩해 '\n' 그대로 전달(Windows \r\n 변환 회피).
            payload = command + f"\nprintf '%s %s\\n' {marker} $?\n"
            self.proc.stdin.write(payload.encode("utf-8"))
            self.proc.stdin.flush()
        except Exception as e:
            return {"output": "", "exit_code": None, "error": f"shell write failed: {e}"}

        lines = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                line = self._q.get(timeout=0.2)
            except queue.Empty:
                continue
            if marker in line:
                parts = line.strip().split()
                try:
                    code = int(parts[-1])
                except (ValueError, IndexError):
                    code = None
                return {"output": "".join(lines), "exit_code": code, "error": None}
            lines.append(line)

        return {"output": "".join(lines), "exit_code": None, "error": "timeout"}

    def close(self):
        try:
            self.proc.stdin.write(b"exit\n")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.terminate()
        except Exception:
            pass


class MockShellSession:
    """오프라인 데모용 쉘 시뮬레이터. docker 없이 curl 결과를 흉내낸다."""
    def __init__(self, *args, **kwargs):
        self.history = []

    def run(self, command, timeout=30):
        self.history.append(command)
        c = command
        # Shellshock 페이로드로 flag.txt를 읽는 curl -> 플래그 반환
        if "() {" in c and "/tmp/flag.txt" in c:
            return {"output": "FLAG{shellshock_rce_2024}\n", "exit_code": 0, "error": None}
        # victim.cgi 정상 요청 -> Hello world
        if "curl" in c and "victim.cgi" in c:
            return {"output": "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
                              "<html><body>Hello world</body></html>\n",
                    "exit_code": 0, "error": None}
        if c.strip().startswith("id"):
            return {"output": "uid=0(root) gid=0(root) groups=0(root)\n", "exit_code": 0, "error": None}
        return {"output": "", "exit_code": 0, "error": None}

    def close(self):
        pass
