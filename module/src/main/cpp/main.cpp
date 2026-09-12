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

// ---------------- 你的内存读取代码 ----------------
bool readMemory(void* addr, void* buffer, size_t size) {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = addr;
    remote[0].iov_len = size;
    return process_vm_readv(getpid(), local, 1, remote, 1, 0) == (ssize_t)size;
}

uint32_t readDword(void* addr) {
    uint32_t val = 0;
    readMemory(addr, &val, sizeof(val));
    return val;
}

float readFloat(void* addr) {
    float val = 0;
    readMemory(addr, &val, sizeof(val));
    return val;
}

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
        uint32_t zombiePtr = readDword((void*)slot);

        if (zombiePtr == 0 || zombiePtr < 0x40000000) continue;

        float x = readFloat((void*)(zombiePtr + 0x38));
        uint32_t hp = readDword((void*)(zombiePtr + 0xD4));

        if (x > 100 && x < 1000 && hp > 0) {
            LOGI("僵尸%d: X=%.1f HP=%u", i, x, hp);
        }
    }
}

void* worker(void*) {
    sleep(5); // 等待游戏加载
    while (true) {
        scanZombies();
        sleep(1); // 每秒扫一次
    }
    return nullptr;
}
// ---------------- 你的内存读取代码结束 ----------------


using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        if (!args || !args->nice_name) return;
        // 这里可以加过滤，但我们直接让所有进程通过，后面再判断
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        // 如果进程是植物大战僵尸，启动我们的线程
        if (args && args->nice_name) {
            const char* process_name = env->GetStringUTFChars(args->nice_name, nullptr);
            if (process_name && strstr(process_name, "com.popcap.pvz_na")) {
                LOGI("PvZInject 开始加载...");
                pthread_t tid;
                pthread_create(&tid, nullptr, worker, nullptr);
                pthread_detach(tid);
            }
            if (process_name) env->ReleaseStringUTFChars(args->nice_name, process_name);
        }
    }

    void preServerSpecialize(ServerSpecializeArgs *args) override {}
    void postServerSpecialize(const ServerSpecializeArgs *args) override {}

private:
    Api *api;
    JNIEnv *env;
};

REGISTER_ZYGISK_MODULE(MyModule)
