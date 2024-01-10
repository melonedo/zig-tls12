"""
Test for TLS connection to top 500 websites.

```
zig build
cd tests
python3 tests.py
```

Tests failure where cURL does not fail are recorded in the `failed` folder.
"""

import asyncio
from subprocess import PIPE, DEVNULL
from typing import Optional
import aiofiles

with open("urls.txt") as f:
    urls = f.read().split("\n")

parallel_num = 50
time_quota = .2


async def test_curl(url: str) -> bool:
    proc = await asyncio.create_subprocess_exec(
        "curl",
        "-s",
        url,
        stdout=DEVNULL,
    )
    await proc.wait()
    return proc.returncode == 0


async def test(url: str) -> Optional[str]:
    proc = await asyncio.create_subprocess_exec(
        "../zig-out/bin/tests",
        stdin=PIPE,
        stdout=PIPE,
        stderr=PIPE,
    )
    try:
        out, err = await proc.communicate(url.encode() + b"\n")
        if proc.returncode != 0:
            return err.decode()
    except asyncio.CancelledError:
        pass
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()


async def timed_test(sem: asyncio.Semaphore, url: str):
    async with sem:
        task = asyncio.create_task(test(url))
        try:
            err = await asyncio.wait_for(task, parallel_num * time_quota)
            if err is not None:
                curl_status = "succeeded" if await test_curl(url) else "failed"
                print(f"Failed <cURL {curl_status}>: {url}")
                if curl_status == "succeeded":
                    async with aiofiles.open(f"failed/{url[7:]}", "wt") as f:
                        await f.write(err)
            else:
                print(f"Succeeded: {url}")
            await task
        except asyncio.TimeoutError:
            print(f"Timeout: {url}")


async def main(urls: list[str]):
    sem = asyncio.Semaphore(parallel_num)
    tasks = [asyncio.create_task(timed_test(sem, url), name=url) for url in urls]
    await asyncio.wait(tasks)


asyncio.run(main(urls))
