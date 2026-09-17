oC‑Recorder‑UAF README.md
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
Attack Vector: Multiple concurrent local threads calling recorder‑related JNI APIs (startRecord, writeFrame, stopRecord). No malicious file required.
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
