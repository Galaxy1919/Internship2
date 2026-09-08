import { NextResponse } from "next/server";
import { spawn, type ChildProcess } from "child_process";
import { existsSync } from "fs";
import path from "path";
import net from "net";

export const runtime = "nodejs";

const PY = process.env.PYTHON || "python3";

// 白名单：所有会传入 CLI 的用户输入都必须在此校验，防命令注入
const CIPHERS = new Set(["aes", "des", "rc4", "ca", "vigenere", "playfair", "multiliteral", "transposition"]);
const PUBKEYS = new Set(["rsa", "elgamal", "sm2"]);
const TRANSPORTS = new Set(["aes", "des", "rc4", "ca"]);

// 从 process.cwd() 向上找仓库根目录（含 DH/encrypt_client.py），兼容从 web/ 或仓库根运行
function findRepoRoot(): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    if (existsSync(path.join(dir, "DH", "encrypt_client.py"))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  throw new Error("找不到仓库根目录（缺少 DH/encrypt_client.py）");
}
const REPO_ROOT = findRepoRoot();

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const port = (srv.address() as net.AddressInfo).port;
      srv.close(() => resolve(port));
    });
  });
}

// 解密端 listen 后会立刻打印 "READY host:port"（flush），轮询它即可，绝不能用连接去探——那会吃掉它唯一的 accept 槽位。
function waitForServerReady(getOutput: () => string, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const check = () => {
      if (getOutput().includes("READY")) return resolve();
      if (Date.now() > deadline) return reject(new Error("解密端启动超时"));
      setTimeout(check, 50);
    };
    check();
  });
}

function run(argv: string[], timeoutMs = 30000): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn(PY, argv, { cwd: REPO_ROOT });
    let stdout = "";
    let stderr = "";
    child.stdout?.on("data", (d) => (stdout += d.toString()));
    child.stderr?.on("data", (d) => (stderr += d.toString()));
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
    }, timeoutMs);
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: null, stdout, stderr: String(err) });
    });
  });
}

function waitForExit(child: ChildProcess, timeoutMs = 5000): Promise<void> {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    const timer = setTimeout(() => {
      try {
        child.kill("SIGKILL");
      } catch {}
      resolve();
    }, timeoutMs);
    child.on("exit", () => {
      clearTimeout(timer);
      resolve();
    });
  });
}

export async function POST(req: Request) {
  let body: Record<string, unknown> = {};
  try {
    body = await req.json();
  } catch {
    /* ignore malformed JSON */
  }
  const mode = typeof body.mode === "string" ? body.mode : "message";
  const rawText = typeof body.text === "string" ? body.text : "";
  const text = rawText.length > 0 ? rawText : "HELLO WORLD";
  const cipher = typeof body.cipher === "string" ? body.cipher : "";
  const transport = typeof body.transport === "string" ? body.transport : "aes";
  const key = typeof body.key === "string" && body.key.length > 0 ? body.key : undefined;

  if (!TRANSPORTS.has(transport)) {
    return NextResponse.json({ ok: false, error: `非法传输密码: ${transport}` }, { status: 400 });
  }

  const clientArgs = ["DH/encrypt_client.py"];
  if (mode === "message") {
    clientArgs.push(text);
  } else if (mode === "cipher") {
    if (!CIPHERS.has(cipher)) {
      return NextResponse.json({ ok: false, error: `非法对称密码: ${cipher}` }, { status: 400 });
    }
    clientArgs.push("--cipher", cipher, "--text", text);
    if (key) clientArgs.push("--key", key);
  } else if (mode === "pubkey") {
    if (!PUBKEYS.has(cipher)) {
      return NextResponse.json({ ok: false, error: `非法公钥密码: ${cipher}` }, { status: 400 });
    }
    clientArgs.push("--pubkey", cipher, "--text", text);
  } else if (mode === "digest") {
    clientArgs.push("--digest", "--text", text);
  } else if (mode === "ecdh") {
    clientArgs.push("--ecdh");
  } else {
    return NextResponse.json({ ok: false, error: `未知模式: ${mode}` }, { status: 400 });
  }
  clientArgs.push("--host", "127.0.0.1", "--transport", transport);

  let port: number;
  try {
    port = await freePort();
  } catch {
    return NextResponse.json({ ok: false, error: "无法分配端口" }, { status: 500 });
  }
  clientArgs.push("--port", String(port));

  const server = spawn(PY, ["DH/decrypt_server.py", "--host", "127.0.0.1", "--port", String(port)], {
    cwd: REPO_ROOT,
  });
  let serverOutput = "";
  server.stdout?.on("data", (d) => (serverOutput += d.toString()));
  server.stderr?.on("data", (d) => (serverOutput += d.toString()));

  try {
    await waitForServerReady(() => serverOutput);
    const client = await run(clientArgs);
    await waitForExit(server);
    return NextResponse.json({
      ok: client.code === 0,
      clientStdout: client.stdout,
      clientStderr: client.stderr,
      serverOutput,
    });
  } catch (e) {
    try {
      server.kill("SIGKILL");
    } catch {}
    return NextResponse.json({ ok: false, error: String(e), serverOutput }, { status: 500 });
  }
}
