#include "../../includes/handler/MappingHandler.h"

#include <iostream>
#include <cstring>
#include <stdexcept>
#include <jvmti.h>
#include <unordered_set>
#include <mutex>
#include <vector>

#include "../../includes/util/Debug.h"
#include "util/JNIUtils.h"

namespace {

    std::unordered_set<std::string> g_loggedMissingClass;
    std::unordered_set<std::string> g_loggedMissingField;
    std::unordered_set<std::string> g_loggedMissingMethod;
    std::unordered_set<std::string> g_loggedMissingObject;
    std::mutex g_loggedMissingMutex;

    void warnOnceMissing(std::unordered_set<std::string>& bucket, const char* kind, const std::string& key) {
        std::lock_guard<std::mutex> lk(g_loggedMissingMutex);
        if (bucket.insert(key).second) {
        }
    }
}

Mappings::Mappings() {
    this->env = nullptr;
    this->method = {};
    this->cachedClassLoader = nullptr;
}

Mappings::~Mappings() {
    clearMappings();
}

static jclass findClassViaRoot(JNIEnv* env, const char* name) {
    jclass c = env->FindClass(name);
    if (!c && env->ExceptionCheck()) env->ExceptionClear();
    return c;
}

static jclass loadClassViaClassLoader(JNIEnv* env, jobject loader, const char* name) {
    if (!loader) return nullptr;

    jclass clClass = env->FindClass("java/lang/ClassLoader");
    if (!clClass) { if (env->ExceptionCheck()) env->ExceptionClear(); return nullptr; }

    jmethodID loadClass = env->GetMethodID(clClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    env->DeleteLocalRef(clClass);
    if (!loadClass) { if (env->ExceptionCheck()) env->ExceptionClear(); return nullptr; }

    std::string dotted = name;
    for (char& ch : dotted) if (ch == '/') ch = '.';

    jstring jname = env->NewStringUTF(dotted.c_str());
    auto c = static_cast<jclass>(env->CallObjectMethod(loader, loadClass, jname));
    env->DeleteLocalRef(jname);
    if (!c && env->ExceptionCheck()) env->ExceptionClear();
    return c;
}

static jobject getClassLoaderOf(JNIEnv* env, jclass c) {
    jclass classClass = env->FindClass("java/lang/Class");
    if (!classClass) { if (env->ExceptionCheck()) env->ExceptionClear(); return nullptr; }

    jmethodID getCL = env->GetMethodID(classClass, "getClassLoader", "()Ljava/lang/ClassLoader;");
    env->DeleteLocalRef(classClass);
    if (!getCL) { if (env->ExceptionCheck()) env->ExceptionClear(); return nullptr; }

    jobject loader = env->CallObjectMethod(c, getCL);
    if (env->ExceptionCheck()) env->ExceptionClear();
    return loader;
}

jclass Mappings::findClass(const std::string &className) const {
    if (!this->env) return nullptr;

    switch (this->method) {
        case ClassResolvingMethod::ROOT_CLASSLOADER: {
            jclass c = findClassViaRoot(this->env, className.c_str());

            if (c && !this->cachedClassLoader) {
                jobject loader = getClassLoaderOf(this->env, c);
                if (loader) {
                    this->cachedClassLoader = this->env->NewGlobalRef(loader);
                    this->env->DeleteLocalRef(loader);
                }
            }
            return c;
        }

        case ClassResolvingMethod::THREADS_CLASSLOADER:
            return findClassWithThreads(this->env, className.c_str());

        case ClassResolvingMethod::SPECIFIC_CLASSLOADER:
        case ClassResolvingMethod::DISCOVERED_CLASSLOADER: {

            if (this->cachedClassLoader) {
                if (jclass c = loadClassViaClassLoader(this->env, this->cachedClassLoader,
                                                      className.c_str())) {
                    return c;
                }
            }

            jclass c = findClassViaJvmti(this->env, className.c_str());
            if (c && !this->cachedClassLoader) {
                jobject loader = getClassLoaderOf(this->env, c);
                if (loader) {
                    this->cachedClassLoader = this->env->NewGlobalRef(loader);
                    this->env->DeleteLocalRef(loader);
                }
            }
            return c;
        }

        default:
            return nullptr;
    }
}

bool Mappings::registerMappingsFromWbin(const unsigned char *data, size_t size) {

    if (!data || size < 8 || !this->env) {
        return false;
    }

    size_t pos = 0;

    auto readU32 = [&]() -> uint32_t {
        if (pos + 4 > size) throw std::runtime_error("unexpected end of wbin");
        uint32_t v;
        memcpy(&v, data + pos, 4);
        pos += 4;
        return v;
    };

    auto readU8 = [&]() -> uint8_t {
        if (pos + 1 > size) throw std::runtime_error("unexpected end of wbin");
        return data[pos++];
    };

    auto readStr = [&]() -> std::string {
        uint32_t len = readU32();
        if (pos + len > size) throw std::runtime_error("unexpected end of wbin");
        std::string s(reinterpret_cast<const char*>(data + pos), len);
        pos += len;
        return s;
    };

    struct PendingMethod { std::string mKey, mName, mSig; char mIsStatic; };
    struct PendingField  { std::string fKey, fName, fSig; char fIsStatic; char fIsGlobal; };
    struct PendingClass {
        std::string classKey, className;
        std::vector<PendingMethod> methods;
        std::vector<PendingField> fields;
    };
    std::vector<PendingClass> pending;

    try {
        if (memcmp(data, "WBIN", 4) != 0) {
            return false;
        }
        pos = 4;

        int failCount = 0;
        uint32_t classCount = readU32();

        pending.reserve(classCount);
        for (uint32_t i = 0; i < classCount; i++) {
            PendingClass pc;
            pc.classKey = readStr();
            pc.className = readStr();

            uint32_t methodCount = readU32();
            pc.methods.reserve(methodCount);
            for (uint32_t j = 0; j < methodCount; j++) {
                PendingMethod pm;
                pm.mKey = readStr();
                pm.mName = readStr();
                pm.mSig = readStr();
                pm.mIsStatic = static_cast<char>(readU8());
                pc.methods.push_back(std::move(pm));
            }
            uint32_t fieldCount = readU32();
            pc.fields.reserve(fieldCount);
            for (uint32_t j = 0; j < fieldCount; j++) {
                PendingField pf;
                pf.fKey = readStr();
                pf.fName = readStr();
                pf.fSig = readStr();
                pf.fIsStatic = static_cast<char>(readU8());
                pf.fIsGlobal = static_cast<char>(readU8());
                pc.fields.push_back(std::move(pf));
            }
            pending.push_back(std::move(pc));
        }

        for (auto& pc : pending) {
            jclass localClazz = findClass(pc.className);
            if (localClazz) {
                jclass global = static_cast<jclass>(this->env->NewGlobalRef(localClazz));
                this->env->DeleteLocalRef(localClazz);
                if (global) this->classes[pc.classKey] = global;
            }
        }

        int retriedOk = 0;
        for (auto& pc : pending) {
            if (this->classes.find(pc.classKey) != this->classes.end()) continue;
            jclass localClazz = findClass(pc.className);
            if (localClazz) {
                jclass global = static_cast<jclass>(this->env->NewGlobalRef(localClazz));
                this->env->DeleteLocalRef(localClazz);
                if (global) {
                    this->classes[pc.classKey] = global;
                    ++retriedOk;
                }
            }
        }
        if (retriedOk > 0) {
        }

        for (auto& pc : pending) {
            const auto itClazz = this->classes.find(pc.classKey);
            jclass clazz = (itClazz != this->classes.end()) ? itClazz->second : nullptr;
            const std::string& classKey = pc.classKey;
            if (!clazz) {
                failCount += 1 + static_cast<int>(pc.methods.size() + pc.fields.size());
                continue;
            }

            for (auto& pm : pc.methods) {
                const std::string& mKey  = pm.mKey;
                const std::string& mName = pm.mName;
                const std::string& mSig  = pm.mSig;
                const char mIsStatic = pm.mIsStatic;

                jmethodID mid = mIsStatic
                    ? this->env->GetStaticMethodID(clazz, mName.c_str(), mSig.c_str())
                    : this->env->GetMethodID(clazz, mName.c_str(), mSig.c_str());
                if (mid) {
                    this->methods[mKey] = mid;
                } else {
                    if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                    failCount++;
                }
            }

            for (auto& pf : pc.fields) {
                const std::string& fKey = pf.fKey;
                const std::string& fName = pf.fName;
                const std::string& fSig = pf.fSig;
                const char fIsStatic = pf.fIsStatic;
                const char fIsGlobal = pf.fIsGlobal;

                const bool needGlobal = fIsGlobal ||
                    (fIsStatic && !fSig.empty() && (fSig[0] == 'L' || fSig[0] == '['));

                if (needGlobal) {
                    jfieldID fid = this->env->GetStaticFieldID(clazz, fName.c_str(), fSig.c_str());
                    if (fid) {
                        this->fields[fKey] = fid;
                        jobject obj = this->env->GetStaticObjectField(clazz, fid);
                        if (!obj) {
                            std::string valuesSig = std::string("()[L") + pc.className + ";";
                            jmethodID valuesMid = this->env->GetStaticMethodID(clazz, "values", valuesSig.c_str());
                            if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                            if (valuesMid) {
                                jobject arr = this->env->CallStaticObjectMethod(clazz, valuesMid);
                                if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                                if (arr) this->env->DeleteLocalRef(arr);
                                obj = this->env->GetStaticObjectField(clazz, fid);
                                if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                            }
                        }
                        if (obj) {
                            jobject global = this->env->NewGlobalRef(obj);
                            if (global) {
                                this->objects[fKey] = global;
                            } else {
                                failCount++;
                            }
                        } else {
                            failCount++;
                        }
                    } else {
                        if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                        failCount++;
                    }
                } else {
                    jfieldID fid = fIsStatic
                        ? this->env->GetStaticFieldID(clazz, fName.c_str(), fSig.c_str())
                        : this->env->GetFieldID(clazz, fName.c_str(), fSig.c_str());
                    if (fid) {
                        this->fields[fKey] = fid;
                    } else {
                        if (this->env->ExceptionCheck()) this->env->ExceptionClear();
                        failCount++;
                    }
                }
            }
        }

        bool hasPlayerInfoList = this->fields.find("playerInfoList") != this->fields.end();
        bool hasResponseTime = this->fields.find("responseTime") != this->fields.end();

        const bool hasEnoughMappings = this->classes.size() > 100 && this->fields.size() > 100;
        const bool acceptableFailRate = failCount < 50;

        if (failCount > 0) {
        }

        const bool result = (failCount == 0) || (hasEnoughMappings && acceptableFailRate);
        return result;
    }
    catch (const std::exception& e) {
        return false;
    }
}

void Mappings::clearMappings() {
    if (this->env) {
        for (auto &pair : this->classes) {
            if (pair.second) {
                this->env->DeleteGlobalRef(pair.second);
            }
        }
        for (auto &pair : this->objects) {
            if (pair.second) {
                this->env->DeleteGlobalRef(pair.second);
            }
        }
        if (this->cachedClassLoader) {
            this->env->DeleteGlobalRef(this->cachedClassLoader);
        }
    }

    this->classes.clear();
    this->fields.clear();
    this->methods.clear();
    this->objects.clear();
    this->cachedClassLoader = nullptr;

    std::lock_guard<std::mutex> lk(g_loggedMissingMutex);
    g_loggedMissingClass.clear();
    g_loggedMissingField.clear();
    g_loggedMissingMethod.clear();
    g_loggedMissingObject.clear();
}

void Mappings::setEnv(JNIEnv* env) {
    this->env = env;
}

void Mappings::setMethod(const ClassResolvingMethod method) {
    this->method = method;
}

jclass Mappings::getClass(const std::string &key) {
    const auto it = this->classes.find(key);
    if (it != this->classes.end()) return it->second;
    warnOnceMissing(g_loggedMissingClass, "class", key);
    return nullptr;
}

jfieldID Mappings::getField(const std::string &key) {
    const auto it = this->fields.find(key);
    if (it != this->fields.end()) return it->second;
    warnOnceMissing(g_loggedMissingField, "field", key);
    return nullptr;
}

jmethodID Mappings::getMethod(const std::string &key) {
    const auto it = this->methods.find(key);
    if (it != this->methods.end()) return it->second;
    warnOnceMissing(g_loggedMissingMethod, "method", key);
    return nullptr;
}

jobject Mappings::getObject(const std::string &key) {
    const auto it = this->objects.find(key);
    if (it != this->objects.end()) return it->second;
    warnOnceMissing(g_loggedMissingObject, "object", key);
    return nullptr;
}

Mappings& Mappings::getInstance() {
    static Mappings instance;
    return instance;
}
