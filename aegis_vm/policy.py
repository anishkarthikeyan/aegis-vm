from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Configurable rules applied during AST inspection."""

    block_imports: bool = True
    block_dangerous_imports: bool = True
    block_eval: bool = True
    block_exec: bool = True
    block_dynamic_execution: bool = True
    block_shell_execution: bool = True
    block_subprocess: bool = True
    block_dunder_attributes: bool = True
    block_path_traversal: bool = True
    block_dangerous_builtins: bool = True
    block_file_writes: bool = True
    block_network: bool = True

    blocked_import_roots: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "os",
                "sys",
                "subprocess",
                "socket",
                "pathlib",
                "shutil",
                "importlib",
                "ctypes",
                "pickle",
                "builtins",
                "pty",
                "fcntl",
                "signal",
                "multiprocessing",
                "threading",
                "urllib",
                "urllib3",
                "http",
                "httpx",
                "requests",
                "aiohttp",
                "ftplib",
                "smtplib",
                "telnetlib",
                "ssl",
                "websocket",
                "paramiko",
                "scapy",
            }
        )
    )

    dynamic_execution_names: frozenset[str] = field(
        default_factory=lambda: frozenset({"compile", "__import__"})
    )

    shell_execution_calls: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "os.system",
                "os.popen",
                "os.spawn",
                "os.spawnl",
                "os.spawnle",
                "os.spawnlp",
                "os.spawnlpe",
                "os.spawnv",
                "os.spawnve",
                "os.spawnvp",
                "os.spawnvpe",
                "os.execl",
                "os.execle",
                "os.execlp",
                "os.execlpe",
                "os.execv",
                "os.execve",
                "os.execvp",
                "os.execvpe",
            }
        )
    )

    subprocess_call_names: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "run",
                "call",
                "Popen",
                "check_output",
                "check_call",
                "getoutput",
                "getstatusoutput",
            }
        )
    )

    network_module_prefixes: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "socket",
                "urllib",
                "urllib3",
                "http",
                "httpx",
                "requests",
                "aiohttp",
                "ftplib",
                "smtplib",
                "telnetlib",
                "ssl",
                "websocket",
                "paramiko",
                "scapy",
            }
        )
    )

    network_call_names: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "urlopen",
                "urlretrieve",
                "connect",
                "create_connection",
                "create_server",
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "head",
                "request",
                "send",
                "recv",
                "recvfrom",
                "sendto",
                "sendall",
            }
        )
    )

    file_write_call_names: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "write_text",
                "write_bytes",
                "writelines",
            }
        )
    )

    file_write_qualified_calls: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "os.write",
                "os.remove",
                "os.unlink",
                "os.rename",
                "os.replace",
                "os.mkdir",
                "os.makedirs",
                "os.rmdir",
                "os.removedirs",
                "shutil.copy",
                "shutil.copy2",
                "shutil.copytree",
                "shutil.move",
                "shutil.rmtree",
                "pathlib.Path.write_text",
                "pathlib.Path.write_bytes",
            }
        )
    )

    dangerous_builtin_names: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "getattr",
                "setattr",
                "delattr",
                "globals",
                "locals",
                "vars",
                "breakpoint",
                "input",
                "help",
            }
        )
    )

    blocked_dunder_names: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "__globals__",
                "__builtins__",
                "__class__",
                "__bases__",
                "__subclasses__",
                "__mro__",
                "__code__",
                "__reduce__",
                "__reduce_ex__",
                "__getattribute__",
                "__setattr__",
                "__delattr__",
                "__dict__",
                "__init__",
                "__import__",
            }
        )
    )

    @classmethod
    def strict(cls) -> SafetyPolicy:
        return cls()

    @classmethod
    def lenient(cls) -> SafetyPolicy:
        """Allow benign imports and reflection; still block execution and I/O risks."""
        return cls(
            block_imports=False,
            block_dunder_attributes=False,
            block_dangerous_builtins=False,
        )
