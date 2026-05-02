# Vuln: LibreDWG dwgbmp R2004 Heap Buffer Overflow

**Project:** LibreDWG/libredwg (https://github.com/LibreDWG/libredwg)  
**Version:** Vulnerable at commit `6d6a33987a1a97095b069c799c3d8a793320f812`, fixed by commit `8f03865f37f5d4ffd616fef802acc980be54d300`  
**Date:** 2026-05-02  
**Severity:** MEDIUM  
**OWASP:** N/A - Native File Parsing Memory Corruption  
**CWE:** CWE-787 - Out-of-bounds Write  

---

## Affected File

```text
src/decode.c (R2004 compressed section decompression path)
programs/dwgbmp.c (trigger path via crafted DWG input)
```

## Root Cause

LibreDWG does not sufficiently validate the destination address and copy size while processing R2004 compressed sections from a crafted DWG file. In the vulnerable commit, malformed metadata can cause an out-of-bounds heap access during decompression. The public issue reports the crash as a heap-buffer-overflow in `bit_read_RC()`, while local reproduction with the same PoC and vulnerable commit also reaches an AddressSanitizer crash in `read_2004_compressed_section()` during `memcpy`.

The vendor fix adds missing boundary checks before copying decompressed data:

```diff
if (info->compressed == 2 || bytes_left < 0
+    || es.fields.address > max_decomp_size
     || es.fields.address + size > max_decomp_size
+    || es.fields.address + size > dec.size
     || offset + size > dat->size)
```

【此处插入一张补丁截图，内容是修复提交 `8f03865f37f5d4ffd616fef802acc980be54d300` 中 `src/decode.c` 新增边界检查的 diff】

## Steps to Reproduce

```bash
git clone https://github.com/LibreDWG/libredwg.git libredwg-vuln
cd libredwg-vuln
git checkout 6d6a33987a1a97095b069c799c3d8a793320f812

sh autogen.sh

CC=clang \
CXX=clang++ \
CFLAGS="-O0 -g -fno-omit-frame-pointer -fsanitize=address -Wno-error" \
CXXFLAGS="-std=c++20 -O0 -g -fno-omit-frame-pointer -fsanitize=address -Wno-error" \
LDFLAGS="-fsanitize=address -no-pie -pthread -ldl -lm" \
./configure \
  --enable-debug \
  --enable-trace \
  --disable-shared \
  --disable-bindings \
  --disable-docs

make -j"$(nproc)"

curl -L -o poc.dwg \
  https://raw.githubusercontent.com/HackC0der/CVE-Repos/main/libredwg/libredwg_6d6a339_heap_oob_write_read_2004_compressed_section.dwg

ASAN_OPTIONS=abort_on_error=1:symbolize=1 \
  ./programs/dwgbmp ./poc.dwg
```

Expected result on the vulnerable commit:

```text
exit code: 134
ERROR: AddressSanitizer: SEGV
WRITE memory access
read_2004_compressed_section .../src/decode.c:2181
get_bmp .../programs/dwgbmp.c:122
main .../programs/dwgbmp.c:342
```

【此处插入一张本地复现终端截图，内容是 vulnerable commit 运行 `dwgbmp poc.dwg` 后的 ASan 崩溃输出】

Optional public evidence:

The public issue for this bug is:

- https://github.com/LibreDWG/libredwg/issues/1248

【此处插入一张 GitHub issue #1248 截图，建议包含标题 `dwgbmp: Heap-buffer-overflow in bit_read_RC at bits.c:281` 和崩溃摘要】

## Impact

A crafted DWG file can trigger an out-of-bounds heap access in `dwgbmp`, causing a process crash and resulting in denial of service. Any workflow or application that automatically parses attacker-controlled DWG files with the vulnerable LibreDWG code path may also be affected.

## Recommended Fix

Apply the upstream fix from commit `8f03865f37f5d4ffd616fef802acc980be54d300`, which adds proper decompression boundary validation before copying data. The fix prevents malformed DWG metadata from writing outside the intended heap buffer.

It is also advisable to keep AddressSanitizer-enabled testing for malformed DWG samples in regression coverage for the R2004 decompression path.

---

## References

- LibreDWG issue #1248: https://github.com/LibreDWG/libredwg/issues/1248
- Fix commit: https://github.com/LibreDWG/libredwg/commit/8f03865f37f5d4ffd616fef802acc980be54d300
- Public PoC sample: https://raw.githubusercontent.com/HackC0der/CVE-Repos/main/libredwg/libredwg_6d6a339_heap_oob_write_read_2004_compressed_section.dwg
- LibreDWG repository: https://github.com/LibreDWG/libredwg

## Notes

This issue should be described as distinct from the earlier publicly known LibreDWG issue associated with `CVE-2025-61154` and GitHub issue `#1180`. The present report concerns GitHub issue `#1248`, vulnerable commit `6d6a33987a1a97095b069c799c3d8a793320f812`, and the upstream fix commit `8f03865f37f5d4ffd616fef802acc980be54d300`.
