import os
import subprocess


def run(host):
    # ruleid: openasy.python.command-injection
    subprocess.run("ping -c 1 " + host, shell=True)
    # ruleid: openasy.python.command-injection
    subprocess.check_output(f"tar xf {host}", shell=True)
    # ruleid: openasy.python.command-injection
    os.system("rm -rf /tmp/" + host)
    # ok: openasy.python.command-injection
    subprocess.run(["ping", "-c", "1", host])
    # ok: openasy.python.command-injection
    subprocess.run("ls -la", shell=True)
    # ok: openasy.python.command-injection
    os.system("uptime")
