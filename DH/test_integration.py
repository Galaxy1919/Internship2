"""自动验收：启动解密端，再运行加密端，检查 DH、AES、HMAC 全链路。"""
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE=Path(__file__).resolve().parent

def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0)); return s.getsockname()[1]

def main():
    port=free_port()
    server=subprocess.Popen([sys.executable,"decrypt_server.py","--port",str(port)],cwd=HERE,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    first=server.stdout.readline().strip()
    if not first.startswith("READY"): raise RuntimeError(first)
    client=subprocess.run([sys.executable,"encrypt_client.py","双机DH与AES联调通过","--port",str(port)],cwd=HERE,text=True,capture_output=True,timeout=10)
    rest=server.communicate(timeout=10)[0]
    print(first); print(client.stdout,end=""); print(rest,end="")
    checks=[client.returncode==0,"SERVER_ACK PASS" in client.stdout,"DH_SHARED 3836" in client.stdout,"DH_SHARED 3836" in rest,"PLAINTEXT 双机DH与AES联调通过" in rest]
    if not all(checks):
        print(client.stderr); raise SystemExit("INTEGRATION FAIL")
    print("INTEGRATION PASS")

if __name__=="__main__": main()
