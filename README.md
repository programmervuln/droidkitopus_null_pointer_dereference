
Overview

./uaf_test --recorder-uaf reproduces a null‑pointer dereference vulnerability (CWE‑476) inside the recorder path of actorapp/droidkit‑opus.

Race condition on global OpusEncoder *_encoder state: one thread invokes cleanupRecorder() to destroy encoder, while a concurrent worker thread calls writeFrame() → opus_encode() using the freed/NULL global encoder pointer, triggering SEGV on zero‑page access.

Vulnerability Details

Repository: actorapp/droidkit‑opus

Affected File: opus/src/main/jni/audio.c

Affected globals: OpusEncoder *_encoder

Affected functions: cleanupRecorder(), writeFrame()

Root Cause: Unsynchronized concurrent access to global encoder pointer (TOCTOU race).
Thread‑A executes cleanupRecorder() → opus_encoder_destroy(_encoder); _encoder = 0;
Thread‑B in writeFrame() uses global _encoder without lock; after pointer‑non‑NULL check, _encoder becomes NULL.

Call opus_encode(_encoder, ...) passes NULL pointer into libopus, causing null‑pointer dereference inside opus_encode().

Impact: Local denial‑of‑service (process crash). No code execution, no privilege escalation.

Attack Vector: Multiple concurrent local threads calling recorder‑related JNI APIs 
(startRecord, writeFrame, stopRecord). No malicious file required.

Reproduce

Compile with ASan enabled (Clang):
clang -fsanitize=address -g test_uaf.c audio.c -o uaf_test -lpthread -lopus

Run PoC
./uaf_test --recorder-uaf
Expected Crash Output
ASan reports SEGV read access on zero‑page inside opus_encode():

AddressSanitizer:DEADLYSIGNAL
==13638==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000090
The signal is caused by a READ memory access.
Hint: address points to the zero page.
    #0  ... in opus_encode (/lib/x86_64-linux-gnu/libopus.so.0)
    #1 ... in writeFrame audio.c:452:19
    #2 ... in thread_recorder_worker test_uaf.c:60:9

    Process aborts and generates core dump.
Crash Root Cause Snippet

OpusEncoder *_encoder = 0;

void cleanupRecorder() {
    if (_encoder) {
        opus_encoder_destroy(_encoder);
        _encoder = 0;
    }
    // ... reset recorder global states
}

int writeFrame(uint8_t *framePcmBytes, unsigned int frameByteCount) {
    // TOCTOU: check _encoder non‑NULL here
    // Concurrent thread can run cleanupRecorder() and set _encoder=0 after check
    nbBytes = opus_encode(_encoder, (opus_int16 *)paddedFrameBytes, cur_frame_size, _packet, max_frame_bytes / 10);
    // Pass NULL _encoder into opus_encode → null‑pointer dereference
}
Mitigation
Add mutex lock to protect all read/write access to global _encoder inside cleanupRecorder() and writeFrame().
Copy global pointer to local variable under lock before usage, avoid TOCTOU race window.
Prevent concurrent recorder initialization/destruction/data‑processing from different threads.

Corresponding MITRE CVE Suggested Description (direct copy)
A null pointer dereference vulnerability (CWE‑476) exists in the recorder implementation of actorapp/droidkit‑opus. 
A time‑of‑check‑to‑time‑use (TOCTOU) race condition occurs on the global OpusEncoder 
*_encoder pointer. After writeFrame() validates that _encoder is non‑NULL, a concurrent
thread can invoke cleanupRecorder() to destroy the encoder and set _encoder to NULL. 
Subsequent invocation of opus_encode() with this NULL pointer triggers a null‑pointer 
dereference, resulting in application denial‑of‑service.

ASAN crash log:
./uaf_test --recorder-uaf
=== Running Recorder UAF PoC (_encoder global state race) ===
AddressSanitizer:DEADLYSIGNAL
=================================================================
==13638==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000090 (pc 0x74880db2c4ad bp 0x74880b1fe540 sp 0x74880b1fe510 T1)
==13638==The signal is caused by a READ memory access.
==13638==Hint: address points to the zero page.
    #0 0x74880db2c4ad in opus_encode (/lib/x86_64-linux-gnu/libopus.so.0+0x3e4ad) (BuildId: 53a29374ac557d631d863d9908ff5bec82f55ba5)
    #1 0x5e55359a5351 in writeFrame /home/lloyd/Documents/droidkit-opus-master/opus/src/main/jni/./audio.c:452:19
    #2 0x5e55359a660c in thread_recorder_worker /home/lloyd/Documents/droidkit-opus-master/opus/src/main/jni/test_uaf.c:60:9
    #3 0x74880d694a82 in start_thread nptl/./nptl/pthread_create.c:442:8
    #4 0x74880d7268df  misc/../sysdeps/unix/sysv/linux/x86_64/clone3.S:81

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libopus.so.0+0x3e4ad) (BuildId: 53a29374ac557d631d863d9908ff5bec82f55ba5) in opus_encode
Thread T1 created by T0 here:
    #0 0x5e553595274c in pthread_create (/home/lloyd/Documents/droidkit-opus-master/opus/src/main/jni/uaf_test+0x8b74c) (BuildId: c46328532cffb6f7d583cc0bca8a0239d3257064)
    #1 0x5e55359a6107 in run_recorder_uaf /home/lloyd/Documents/droidkit-opus-master/opus/src/main/jni/test_uaf.c:72:5
    #2 0x5e55359a6107 in main /home/lloyd/Documents/droidkit-opus-master/opus/src/main/jni/test_uaf.c:101:16
    #3 0x74880d629d8f in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16

Stats: 3M malloced (0M for red zones) by 468 calls
Stats: 0M realloced by 51 calls
Stats: 3M freed by 457 calls
Stats: 0M really freed by 0 calls
Stats: 6M (6M-0M) mmaped; 102 maps, 0 unmaps
  mallocs by size class: 3:54; 4:2; 11:1; 14:1; 18:1; 21:51; 23:51; 25:1; 32:51; 33:102; 37:51; 41:51; 46:51;
Stats: malloc large: 0
Stats: StackDepot: 32 ids; 9M allocated
Stats: SizeClassAllocator64: 5M mapped (4M rss) in 1344 allocations; remains 1344
  03 (    48): mapped:     64K allocs:     256 frees:       0 inuse:    256 num_freed_chunks    1109 avail:   1365 rss:      8K releases:      0 last released:      0K region: 0x603000000000
  04 (    64): mapped:     64K allocs:     128 frees:       0 inuse:    128 num_freed_chunks     896 avail:   1024 rss:      4K releases:      0 last released:      0K region: 0x604000000000
  11 (   176): mapped:     64K allocs:     128 frees:       0 inuse:    128 num_freed_chunks     244 avail:    372 rss:      4K releases:      0 last released:      0K region: 0x60b000000000
  14 (   224): mapped:     64K allocs:     128 frees:       0 inuse:    128 num_freed_chunks     164 avail:    292 rss:      4K releases:      0 last released:      0K region: 0x60e000000000
  18 (   384): mapped:     64K allocs:     128 frees:       0 inuse:    128 num_freed_chunks      42 avail:    170 rss:      4K releases:      0 last released:      0K region: 0x612000000000
  21 (   640): mapped:     64K allocs:     102 frees:       0 inuse:    102 num_freed_chunks       0 avail:    102 rss:     36K releases:      0 last released:      0K region: 0x615000000000
  23 (   896): mapped:     64K allocs:      73 frees:       0 inuse:     73 num_freed_chunks       0 avail:     73 rss:     48K releases:      0 last released:      0K region: 0x617000000000
  25 (  1280): mapped:     64K allocs:      51 frees:       0 inuse:     51 num_freed_chunks       0 avail:     51 rss:      4K releases:      0 last released:      0K region: 0x619000000000
  32 (  4096): mapped:    256K allocs:      64 frees:       0 inuse:     64 num_freed_chunks       0 avail:     64 rss:    216K releases:      0 last released:      0K region: 0x620000000000
  33 (  5120): mapped:    576K allocs:     108 frees:       0 inuse:    108 num_freed_chunks       7 avail:    115 rss:    560K releases:      0 last released:      0K region: 0x621000000000
  36 (  8192): mapped:    128K allocs:      16 frees:       0 inuse:     16 num_freed_chunks       0 avail:     16 rss:     24K releases:      0 last released:      0K region: 0x624000000000
  37 ( 10240): mapped:    576K allocs:      54 frees:       0 inuse:     54 num_freed_chunks       3 avail:     57 rss:    432K releases:      0 last released:      0K region: 0x625000000000
  41 ( 20480): mapped:   1088K allocs:      54 frees:       0 inuse:     54 num_freed_chunks       0 avail:     54 rss:    432K releases:      0 last released:      0K region: 0x629000000000
  46 ( 49152): mapped:   2624K allocs:      54 frees:       0 inuse:     54 num_freed_chunks       0 avail:     54 rss:   2376K releases:      0 last released:      0K region: 0x62e000000000
Stats: LargeMmapAllocator: allocated 0 times, remains 0 (0 K) max 0 M; by size logs:
Quarantine limits: global: 256Mb; thread local: 1024Kb
Global quarantine stats: batches: 4; bytes: 4230564 (user: 4197796); chunks: 464 (capacity: 4084); 11% chunks used; 0% memory overhead
==13638==ABORTING
Aborted (core dumped)

