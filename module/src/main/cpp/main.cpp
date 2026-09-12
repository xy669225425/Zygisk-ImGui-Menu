#include <cstring>
#include <jni.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/uio.h>
#include <link.h>
#include <cstdio>
#include <android/log.h>
#include "hook.h"
#include "zygisk.hpp"

#define LOG_TAG "PvZInject"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

uintptr_t getModuleBase(const char* moduleName) {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, moduleName)) {
            sscanf(line, "%lx-", &base);
            break;
        }
    }
    fclose(fp);
    return base;
}

void scanZombies() {
    uintptr_t base = getModuleBase("libpvz.so");
    if (base == 0) return;
    uintptr_t arrayAddr = base + 0xCE164C;

    for (int i = 0; i < 50; i++) {
        uintptr_t slot = arrayAddr + i * 0xC;
        uint32_t zombiePtr = 0;
        struct iovec local[1], remote[1];
        local[0].iov_base = &zombiePtr; local[0].iov_len = 4;
        remote[0].iov_base = (void*)slot; remote[0].iov_len = 4;
        process_vm_readv(getpid(), local, 1, remote, 1, 0);

        if (zombiePtr == 0 || zombiePtr < 0x40000000) continue;

        float x = 0;
        local[0].iov_base = &x; local[0].iov_len = 4;
        remote[0].iov_base = (void*)(zombiePtr + 0x38); remote[0].iov_len = 4;
        process_vm_readv(getpid(), local, 1, remote, 1, 0);

        uint32_t hp = 0;
        local[0].iov_base = &hp; local[0].iov_len = 4;
        remote[0].iov_base = (void*)(zombiePtr + 0xD4); remote[0].iov_len = 4;
        process_vm_readv(getpid(), local, 1, remote, 1, 0);

        if (x > 100 && x < 1000 && hp > 0) {
            LOGI("僵尸%d: X=%.1f HP=%u", i, x, hp);
        }
    }
}

void* worker(void*) {
    sleep(5);
    while (true) { scanZombies(); sleep(1); }
    return nullptr;
}

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override { this->api = api; this->env = env; }
    void preAppSpecialize(AppSpecializeArgs *args) override { if (!args || !args->nice_name) return; }
    void postAppSpecialize(const AppSpecializeArgs *args) override {
        if (args && args->nice_name) {
            const char* p = env->GetStringUTFChars(args->nice_name, nullptr);
            if (p && strstr(p, "com.popcap.pvz_na")) {
                LOGI("PvZInject 开始加载...");
                pthread_t tid; pthread_create(&tid, nullptr, worker, nullptr); pthread_detach(tid);
            }
            if (p) env->ReleaseStringUTFChars(args->nice_name, p);
        }
    }
    void preServerSpecialize(ServerSpecializeArgs *args) override {}
    void postServerSpecialize(const ServerSpecializeArgs *args) override {}
private:
    Api *api; JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
