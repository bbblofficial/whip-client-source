#include "../includes/hook/instrumentation.h"
#include "../includes/hook/classfile.hpp"
#include "../includes/hook/uuid.hpp"
#include "../includes/util/Debug.h"

#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <cstring>

struct method_info_t {
    std::string name;
    std::string signature;
    jint access_flags;
};

static std::unordered_map<std::string, std::unique_ptr<ClassFile>> g_original_class_cache;
static std::unordered_map<std::string, std::unique_ptr<ClassFile>> g_class_file_cache;
static std::unordered_set<std::string> g_classes_to_cache;

static std::unordered_map<std::string, std::vector<uint8_t>> g_redefine_override;

static std::vector<jclass> g_transformed_classes;

struct TransformState {
    jclass classRef;
    std::string className;
    bool successfullyTransformed;
    bool successfullyRestored;
};
static std::vector<TransformState> g_transform_states;

static std::recursive_mutex g_cache_mutex;

static JvmInstrumentor* g_Instance = nullptr;

static bool has_our_hook_marker(const std::vector<uint8_t>& class_bytes) {
    static const char MARKER[] = "org/apache/commons/internal/PerfCounter";
    static constexpr size_t MARKER_LEN = sizeof(MARKER) - 1;

    if (class_bytes.size() < 10) return false;
    const uint8_t* p = class_bytes.data();
    if (p[0] != 0xCA || p[1] != 0xFE || p[2] != 0xBA || p[3] != 0xBE) return false;
    size_t pos = 8;
    if (pos + 2 > class_bytes.size()) return false;
    uint16_t cp_count = (uint16_t(p[pos]) << 8) | p[pos + 1];
    pos += 2;

    for (uint16_t i = 1; i < cp_count; ++i) {
        if (pos >= class_bytes.size()) return false;
        uint8_t tag = p[pos++];
        switch (tag) {
            case 1: {
                if (pos + 2 > class_bytes.size()) return false;
                uint16_t len = (uint16_t(p[pos]) << 8) | p[pos + 1];
                pos += 2;
                if (pos + len > class_bytes.size()) return false;
                if (len == MARKER_LEN &&
                    std::memcmp(p + pos, MARKER, MARKER_LEN) == 0) {
                    return true;
                }
                pos += len;
                break;
            }
            case 7: case 8: case 16: case 19: case 20: pos += 2; break;
            case 15: pos += 3; break;
            case 3: case 4: case 9: case 10: case 11: case 12: case 17: case 18:
                pos += 4; break;
            case 5: case 6:
                pos += 8;
                ++i;
                break;
            default: return false;
        }
    }
    return false;
}

static std::string get_class_name(JNIEnv *env, jclass clazz) {
    jclass klass = env->FindClass("java/lang/Class");
    if (!klass) return "";

    jmethodID getName_method = env->GetMethodID(klass, "getName", "()Ljava/lang/String;");
    if (!getName_method) {
        env->DeleteLocalRef(klass);
        return "";
    }

    jstring name_obj = reinterpret_cast<jstring>(env->CallObjectMethod(clazz, getName_method));
    if (!name_obj) {
        env->DeleteLocalRef(klass);
        return "";
    }

    const char *c_name = env->GetStringUTFChars(name_obj, 0);
    if (!c_name) {
        env->DeleteLocalRef(name_obj);
        env->DeleteLocalRef(klass);
        return "";
    }

    std::string name = std::string(c_name, &c_name[strlen(c_name)]);
    env->ReleaseStringUTFChars(name_obj, c_name);
    env->DeleteLocalRef(name_obj);
    env->DeleteLocalRef(klass);

    for (size_t i = 0; i < name.length(); ++i) {
        if (name[i] == '.') name[i] = '/';
    }
    return name;
}

static std::unique_ptr<method_info_t> get_method_info(jvmtiEnv *jvmti, jmethodID method) {
    char *name;
    char *sig;
    jint access_flags;

    jvmtiError nameErr = jvmti->GetMethodName(method, &name, &sig, NULL);
    if (nameErr != JVMTI_ERROR_NONE) {
        std::cerr << "[get_method_info] GetMethodName failed for jmethodID=" << method
                  << " err=" << nameErr << std::endl;
        return nullptr;
    }
    jvmtiError modErr = jvmti->GetMethodModifiers(method, &access_flags);
    if (modErr != JVMTI_ERROR_NONE) {
        std::cerr << "[get_method_info] GetMethodModifiers failed for " << name << sig
                  << " err=" << modErr << std::endl;
        jvmti->Deallocate(reinterpret_cast<unsigned char *>(name));
        jvmti->Deallocate(reinterpret_cast<unsigned char *>(sig));
        return nullptr;
    }

    auto info = std::make_unique<method_info_t>(method_info_t {
        std::string(name),
        std::string(sig),
        access_flags
    });

    jvmti->Deallocate(reinterpret_cast<unsigned char *>(name));
    jvmti->Deallocate(reinterpret_cast<unsigned char *>(sig));
    return info;
}

static void JNICALL JNIHook_ClassFileLoadHook(jvmtiEnv *jvmti_env,
                                       JNIEnv* jni_env,
                                       jclass class_being_redefined,
                                       jobject loader,
                                       const char* name,
                                       jobject protection_domain,
                                       jint class_data_len,
                                       const unsigned char* class_data,
                                       jint* new_class_data_len,
                                       unsigned char** new_class_data)
{
    if (!name) return;

    bool interested = false;
    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);
        interested = g_classes_to_cache.count(name) > 0;
    }

    if (!interested) return;

    std::string className = name;
    std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);

    if (!class_data || class_data_len == 0) {
        std::cerr << "[ClassFileLoadHook] Invalid class data for: " << className << std::endl;
        return;
    }

    auto cf = ClassFile::load(class_data);

    if (!cf) {
        std::cerr << "[ClassFileLoadHook] Failed to parse ClassFile for: " << className << std::endl;
        return;
    }

    auto origIt = g_original_class_cache.find(className);
    if (origIt == g_original_class_cache.end()) {

        auto cf_copy = ClassFile::load(class_data);
        if (cf_copy) {
            g_original_class_cache[className] = std::move(cf_copy);
        }
    }

    g_class_file_cache[className] = std::move(cf);

    auto overrideIt = g_redefine_override.find(className);
    if (overrideIt != g_redefine_override.end() && new_class_data && new_class_data_len) {
        const std::vector<uint8_t>& bytes = overrideIt->second;
        unsigned char* alloc = nullptr;
        jvmtiError ae = jvmti_env->Allocate(static_cast<jlong>(bytes.size()), &alloc);
        if (ae == JVMTI_ERROR_NONE && alloc) {
            std::memcpy(alloc, bytes.data(), bytes.size());
            *new_class_data = alloc;
            *new_class_data_len = static_cast<jint>(bytes.size());
        } else {
            std::cerr << "[ClassFileLoadHook] OVERRIDE: jvmti->Allocate failed for "
                      << className << " err=" << ae << std::endl;
        }
        g_redefine_override.erase(overrideIt);
    }
}

JvmInstrumentor& JvmInstrumentor::Get() {
    static JvmInstrumentor instance;
    g_Instance = &instance;
    return instance;
}

bool JvmInstrumentor::Initialize(JavaVM* vm) {
    if (m_Initialized) return true;
    m_Jvm = vm;

    if (m_Jvm->GetEnv(reinterpret_cast<void **>(&m_Jvmti), JVMTI_VERSION_1_2) != JNI_OK) {
        std::cerr << "[JvmInstrumentor] Failed to get JVMTI env" << std::endl;
        return false;
    }

    jvmtiCapabilities capabilities;
    memset(&capabilities, 0, sizeof(capabilities));
    if (m_Jvmti->GetPotentialCapabilities(&capabilities) != JVMTI_ERROR_NONE) {
        return false;
    }

    jvmtiCapabilities requested_caps;
    memset(&requested_caps, 0, sizeof(requested_caps));
    if (capabilities.can_redefine_classes) requested_caps.can_redefine_classes = 1;
    if (capabilities.can_redefine_any_class) requested_caps.can_redefine_any_class = 1;
    if (capabilities.can_retransform_classes) requested_caps.can_retransform_classes = 1;
    if (capabilities.can_retransform_any_class) requested_caps.can_retransform_any_class = 1;
    if (capabilities.can_suspend) requested_caps.can_suspend = 1;

    if (m_Jvmti->AddCapabilities(&requested_caps) != JVMTI_ERROR_NONE) {
        std::cerr << "[JvmInstrumentor] Failed to add JVMTI capabilities" << std::endl;
        return false;
    }

    jvmtiEventCallbacks callbacks = {};
    callbacks.ClassFileLoadHook = JNIHook_ClassFileLoadHook;
    if (m_Jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks)) != JVMTI_ERROR_NONE) {
        return false;
    }

    m_Initialized = true;

    return true;
}

void JvmInstrumentor::RevertAll(jobject classLoader) {
    if (!m_Initialized) return;

    JNIEnv* env = nullptr;
    bool needDetach = false;

    if (m_Jvm) {
        jint result = m_Jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (result == JNI_EDETACHED) {

            if (m_Jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) {
                needDetach = true;
            } else {
                std::cerr << "[JvmInstrumentor] Failed to attach thread for RevertAll!" << std::endl;
                env = nullptr;
            }
        }
    }

    if (env && m_Jvmti) {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);

        jthread curthread;
        jthread *threads = nullptr;
        jint thread_count = 0;

        if (m_Jvmti->GetCurrentThread(&curthread) == JVMTI_ERROR_NONE &&
            m_Jvmti->GetAllThreads(&thread_count, &threads) == JVMTI_ERROR_NONE) {

            for (jint i = 0; i < thread_count; ++i) {
                if (threads[i] && !env->IsSameObject(threads[i], curthread)) {
                    m_Jvmti->SuspendThread(threads[i]);
                }
            }
        }

        for (auto& state : g_transform_states) {
            if (!state.classRef) continue;

            std::string className = get_class_name(env, state.classRef);
            if (className.empty()) {
                env->DeleteGlobalRef(state.classRef);
                state.successfullyRestored = false;
                continue;
            }

            auto it = g_original_class_cache.find(className);
            if (it != g_original_class_cache.end() && it->second) {
                const auto& originalBytes = it->second->get_original_bytes();

                if (!originalBytes.empty()) {

                    jvmtiClassDefinition classDef;
                    classDef.klass = state.classRef;
                    classDef.class_byte_count = static_cast<jint>(originalBytes.size());
                    classDef.class_bytes = reinterpret_cast<const unsigned char*>(originalBytes.data());

                    jvmtiError err = m_Jvmti->RedefineClasses(1, &classDef);
                    if (err != JVMTI_ERROR_NONE) {
                        std::cerr << "[JvmInstrumentor] CRITICAL: Failed to restore original bytecode for "
                                  << className << " (JVMTI error " << err << ")" << std::endl;
                        std::cerr << "[JvmInstrumentor] This will cause DOUBLE-HOOKING on re-injection!" << std::endl;
                        state.successfullyRestored = false;
                    } else {
                        state.successfullyRestored = true;
                    }
                } else {
                    std::cerr << "[JvmInstrumentor] CRITICAL: No original bytes found for " << className << std::endl;
                    state.successfullyRestored = false;
                }
            } else {
                std::cerr << "[JvmInstrumentor] CRITICAL: ClassFile cache missing for " << className << std::endl;
                state.successfullyRestored = false;
            }

            env->DeleteGlobalRef(state.classRef);
        }

        g_transformed_classes.clear();
        g_transform_states.clear();

        if (threads) {
            for (jint i = 0; i < thread_count; ++i) {
                if (threads[i] && !env->IsSameObject(threads[i], curthread)) {
                    m_Jvmti->ResumeThread(threads[i]);
                }
            }
            m_Jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));
        }

        g_class_file_cache.clear();
    }

    if (needDetach && m_Jvm) {
        m_Jvm->DetachCurrentThread();
    }
}

bool JvmInstrumentor::Shutdown() {
    if (!m_Initialized) return true;

    RevertAll(nullptr);

    if (m_Jvmti) {
        jvmtiEventCallbacks callbacks = {};
        m_Jvmti->SetEventCallbacks(&callbacks, sizeof(callbacks));
        m_Jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
    }

    m_Jvm = nullptr;
    m_Jvmti = nullptr;
    m_Initialized = false;

    return true;
}

bool JvmInstrumentor::RestoreClass(const std::string& className) {
    if (!m_Initialized) return false;

    JNIEnv* env = nullptr;
    bool needDetach = false;

    if (m_Jvm) {
        jint result = m_Jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8);
        if (result == JNI_EDETACHED) {
            if (m_Jvm->AttachCurrentThread(reinterpret_cast<void**>(&env), nullptr) == JNI_OK) {
                needDetach = true;
            } else {
                std::cerr << "[JvmInstrumentor] Failed to attach thread for RestoreClass!" << std::endl;
                return false;
            }
        }
    }

    if (!env || !m_Jvmti) {
        if (needDetach && m_Jvm) m_Jvm->DetachCurrentThread();
        return false;
    }

    bool restored = false;

    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);

        auto it = std::find_if(g_transform_states.begin(), g_transform_states.end(),
            [&className](const TransformState& state) {
                return state.className == className;
            });

        if (it == g_transform_states.end()) {
            std::cerr << "[JvmInstrumentor] Class not found in tracking: " << className << std::endl;
            if (needDetach && m_Jvm) m_Jvm->DetachCurrentThread();
            return false;
        }

        auto cacheIt = g_original_class_cache.find(className);
        if (cacheIt == g_original_class_cache.end() || !cacheIt->second) {
            std::cerr << "[JvmInstrumentor] Original bytecode not found for: " << className << std::endl;
            if (needDetach && m_Jvm) m_Jvm->DetachCurrentThread();
            return false;
        }

        const auto& originalBytes = cacheIt->second->get_original_bytes();
        if (originalBytes.empty()) {
            std::cerr << "[JvmInstrumentor] Empty original bytecode for: " << className << std::endl;
            if (needDetach && m_Jvm) m_Jvm->DetachCurrentThread();
            return false;
        }

        jthread curthread;
        jthread* threads = nullptr;
        jint thread_count = 0;

        if (m_Jvmti->GetCurrentThread(&curthread) == JVMTI_ERROR_NONE &&
            m_Jvmti->GetAllThreads(&thread_count, &threads) == JVMTI_ERROR_NONE) {

            for (jint i = 0; i < thread_count; ++i) {
                if (threads[i] && !env->IsSameObject(threads[i], curthread)) {
                    m_Jvmti->SuspendThread(threads[i]);
                }
            }
        }

        jvmtiClassDefinition classDef;
        classDef.klass = it->classRef;
        classDef.class_byte_count = static_cast<jint>(originalBytes.size());
        classDef.class_bytes = reinterpret_cast<const unsigned char*>(originalBytes.data());

        jvmtiError err = m_Jvmti->RedefineClasses(1, &classDef);

        if (threads) {
            for (jint i = 0; i < thread_count; ++i) {
                if (threads[i] && !env->IsSameObject(threads[i], curthread)) {
                    m_Jvmti->ResumeThread(threads[i]);
                }
            }
            m_Jvmti->Deallocate(reinterpret_cast<unsigned char*>(threads));
        }

        if (err != JVMTI_ERROR_NONE) {
            std::cerr << "[JvmInstrumentor] Failed to restore class " << className
                      << " (error " << err << ")" << std::endl;
            restored = false;
        } else {
            env->DeleteGlobalRef(it->classRef);

            g_transformed_classes.erase(
                std::remove(g_transformed_classes.begin(), g_transformed_classes.end(), it->classRef),
                g_transformed_classes.end()
            );
            g_transform_states.erase(it);

            g_original_class_cache.erase(className);
            g_class_file_cache.erase(className);

            restored = true;
        }
    }

    if (needDetach && m_Jvm) {
        m_Jvm->DetachCurrentThread();
    }

    return restored;
}

jnihook_result_t JvmInstrumentor::Instrument(jmethodID method, InstrumentRawCallback callback) {
    if (!m_Initialized) return JNIHOOK_ERR_GET_JVMTI;

    JNIEnv *env;
    if (m_Jvm->GetEnv(reinterpret_cast<void **>(&env), JNI_VERSION_1_8)) return JNIHOOK_ERR_GET_JNI;

    jclass clazz;
    if (m_Jvmti->GetMethodDeclaringClass(method, &clazz) != JVMTI_ERROR_NONE) {
        return JNIHOOK_ERR_JVMTI_OPERATION;
    }

    std::string clazz_name = get_class_name(env, clazz);
    if (clazz_name.empty()) {
        return JNIHOOK_ERR_JNI_OPERATION;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);
        auto it = g_original_class_cache.find(clazz_name);
        if (it == g_original_class_cache.end()) {

            g_classes_to_cache.insert(clazz_name);

            m_Jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);

            m_Jvmti->RetransformClasses(1, &clazz);

            m_Jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
        }

        if (g_original_class_cache.find(clazz_name) == g_original_class_cache.end()) {
             return JNIHOOK_ERR_CLASS_FILE_CACHE;
        }
    }

    std::vector<uint8_t> bytes_to_transform;
    bool isFirstTransformOnThisClass = false;
    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);

        auto transformIt = std::find_if(g_transform_states.begin(), g_transform_states.end(),
            [&clazz, env](const TransformState& state) {
                return env->IsSameObject(state.classRef, clazz);
            });

        if (transformIt != g_transform_states.end()) {

            m_Jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);

            g_classes_to_cache.insert(clazz_name);
            jvmtiError retransErr = m_Jvmti->RetransformClasses(1, &clazz);

            m_Jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);

            if (retransErr == JVMTI_ERROR_NONE) {
                bytes_to_transform = g_class_file_cache[clazz_name]->bytes();
            } else {
                std::cerr << "[JvmInstrumentor] WARNING: RetransformClasses failed (err=" << retransErr << "), using cached bytes" << std::endl;
                bytes_to_transform = g_class_file_cache[clazz_name]->bytes();
            }
        } else {

            bytes_to_transform = g_class_file_cache[clazz_name]->bytes();
            isFirstTransformOnThisClass = true;
        }
    }

    auto mi = get_method_info(m_Jvmti, method);
    if (!mi) return JNIHOOK_ERR_JVMTI_OPERATION;

    if (isFirstTransformOnThisClass && has_our_hook_marker(bytes_to_transform)) {
        std::cerr << "[JvmInstrumentor] WARNING: " << clazz_name
                  << " already contains PerfCounter hook calls on first transform — "
                  << "JVM tracking gave us a previously-redefined bytecode. "
                  << "Skipping to avoid stacked hooks." << std::endl;
        return JNIHOOK_ERR_CLASS_FILE_CACHE;
    }

    std::vector<uint8_t> new_bytes = callback(bytes_to_transform, mi->name, mi->signature);
    if (new_bytes.empty()) {
        return JNIHOOK_OK;
    }

    auto new_cf = ClassFile::load(new_bytes.data());
    if (!new_cf) {
        std::cerr << "[JvmInstrumentor] Failed to parse modified bytecode" << std::endl;
        return JNIHOOK_ERR_CLASS_FILE_CACHE;
    }

    jvmtiClassDefinition class_def;
    class_def.klass = clazz;
    class_def.class_byte_count = static_cast<jint>(new_bytes.size());
    class_def.class_bytes = new_bytes.data();

    jvmtiError err = m_Jvmti->RedefineClasses(1, &class_def);

    if (err != JVMTI_ERROR_NONE) {
        std::cerr << "[JvmInstrumentor] RedefineClasses failed: " << err << std::endl;
        return JNIHOOK_ERR_JVMTI_OPERATION;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);

        bool alreadyTracked = false;
        for (const auto& state : g_transform_states) {
            if (env->IsSameObject(state.classRef, clazz)) {
                alreadyTracked = true;
                break;
            }
        }

        if (!alreadyTracked) {
            jclass globalClassRef = (jclass)env->NewGlobalRef(clazz);
            if (globalClassRef) {

                g_transformed_classes.push_back(globalClassRef);

                TransformState state;
                state.classRef = globalClassRef;
                state.className = clazz_name;
                state.successfullyTransformed = true;
                state.successfullyRestored = false;
                g_transform_states.push_back(state);
            }
        }
    }

    return JNIHOOK_OK;
}

jnihook_result_t JvmInstrumentor::InstrumentBatch(const std::vector<BatchEntry>& entries) {
    if (!m_Initialized || entries.empty()) {
        std::cout << "[InstrumentBatch] ERROR: Not initialized or empty entries" << std::endl;
        return JNIHOOK_ERR_GET_JVMTI;
    }

    JNIEnv* env;
    if (m_Jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_8)) {
        std::cout << "[InstrumentBatch] ERROR: Failed to get JNIEnv" << std::endl;
        return JNIHOOK_ERR_GET_JNI;
    }

    struct ClassGroup {
        jclass clazz;
        std::string className;
        std::vector<size_t> entryIndices;
    };
    std::vector<ClassGroup> groups;

    for (size_t i = 0; i < entries.size(); ++i) {
        jclass clazz;
        if (m_Jvmti->GetMethodDeclaringClass(entries[i].method, &clazz) != JVMTI_ERROR_NONE) {
            std::cout << "[InstrumentBatch] ERROR: GetMethodDeclaringClass failed for entry " << i << std::endl;
            return JNIHOOK_ERR_JVMTI_OPERATION;
        }

        bool found = false;
        for (auto& g : groups) {
            if (env->IsSameObject(g.clazz, clazz)) {
                g.entryIndices.push_back(i);
                found = true;
                break;
            }
        }
        if (!found) {
            std::string name = get_class_name(env, clazz);
            if (name.empty()) {
                std::cout << "[InstrumentBatch] ERROR: get_class_name returned empty for entry " << i << std::endl;
                return JNIHOOK_ERR_JNI_OPERATION;
            }
            groups.push_back({clazz, name, {i}});
        }
    }

    struct PreparedClass {
        jclass clazz;
        std::string className;
        std::vector<uint8_t> transformedBytes;
        size_t hookCount;
    };
    std::vector<PreparedClass> prepared;

    std::vector<jclass> classesToCapture;
    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);
        for (auto& group : groups) {
            g_classes_to_cache.insert(group.className);
            if (g_original_class_cache.find(group.className) == g_original_class_cache.end()) {
                classesToCapture.push_back(group.clazz);
            }
        }
    }

    if (!classesToCapture.empty()) {
        m_Jvmti->SetEventNotificationMode(JVMTI_ENABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
        m_Jvmti->RetransformClasses(static_cast<jint>(classesToCapture.size()), classesToCapture.data());
        m_Jvmti->SetEventNotificationMode(JVMTI_DISABLE, JVMTI_EVENT_CLASS_FILE_LOAD_HOOK, NULL);
    }

    for (auto& group : groups) {
        const std::string& clazz_name = group.className;
        jclass clazz = group.clazz;

        std::vector<uint8_t> current_bytes;
        {
            std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);
            if (g_original_class_cache.find(clazz_name) == g_original_class_cache.end()) {
                std::cout << "[InstrumentBatch] ERROR: Original bytecode cache miss for " << clazz_name << std::endl;
                return JNIHOOK_ERR_CLASS_FILE_CACHE;
            }

            auto cacheIt = g_class_file_cache.find(clazz_name);
            if (cacheIt == g_class_file_cache.end() || !cacheIt->second) {
                std::cout << "[InstrumentBatch] ERROR: Class file cache miss for " << clazz_name << std::endl;
                return JNIHOOK_ERR_CLASS_FILE_CACHE;
            }
            current_bytes = cacheIt->second->bytes();
            if (current_bytes.empty()) {
                std::cout << "[InstrumentBatch] ERROR: bytes() returned empty for " << clazz_name << std::endl;
                return JNIHOOK_ERR_CLASS_FILE_CACHE;
            }
        }

        for (size_t idx : group.entryIndices) {
            auto mi = get_method_info(m_Jvmti, entries[idx].method);
            if (!mi) {
                std::cout << "[InstrumentBatch] ERROR: get_method_info failed for entry " << idx << std::endl;
                return JNIHOOK_ERR_JVMTI_OPERATION;
            }

            std::cout << "[InstrumentBatch] Transforming " << clazz_name << "." << mi->name << mi->signature << std::endl;
            std::vector<uint8_t> new_bytes = entries[idx].callback(current_bytes, mi->name, mi->signature);
            if (new_bytes.empty()) {
                std::cout << "[InstrumentBatch] ERROR: Transform callback returned empty for " << clazz_name << "." << mi->name << std::endl;
                return JNIHOOK_ERR_CLASS_FILE_CACHE;
            }
            current_bytes = std::move(new_bytes);
        }

        prepared.push_back({clazz, clazz_name, std::move(current_bytes), group.entryIndices.size()});
    }

    std::cout << "[InstrumentBatch] Applying all " << prepared.size() << " classes in one RedefineClasses call..." << std::endl;

    std::vector<jvmtiClassDefinition> classDefs(prepared.size());
    for (size_t i = 0; i < prepared.size(); ++i) {
        classDefs[i].klass = prepared[i].clazz;
        classDefs[i].class_byte_count = static_cast<jint>(prepared[i].transformedBytes.size());
        classDefs[i].class_bytes = prepared[i].transformedBytes.data();
    }

    jvmtiError err = m_Jvmti->RedefineClasses(static_cast<jint>(classDefs.size()), classDefs.data());

    if (err != JVMTI_ERROR_NONE) {
        std::cout << "[InstrumentBatch] ERROR: RedefineClasses failed for batch of "
                  << classDefs.size() << " classes: " << err << std::endl;
        return JNIHOOK_ERR_JVMTI_OPERATION;
    }

    {
        std::lock_guard<std::recursive_mutex> lock(g_cache_mutex);
        for (auto& p : prepared) {
            bool alreadyTracked = false;
            for (const auto& state : g_transform_states) {
                if (env->IsSameObject(state.classRef, p.clazz)) {
                    alreadyTracked = true;
                    break;
                }
            }
            if (!alreadyTracked) {
                jclass globalClassRef = (jclass)env->NewGlobalRef(p.clazz);
                if (globalClassRef) {
                    g_transformed_classes.push_back(globalClassRef);
                    TransformState state;
                    state.classRef = globalClassRef;
                    state.className = p.className;
                    state.successfullyTransformed = true;
                    state.successfullyRestored = false;
                    g_transform_states.push_back(state);
                }
            }

            std::cout << "[InstrumentBatch] Applied " << p.hookCount << " hooks to " << p.className << std::endl;
        }
    }

    std::cout << "[InstrumentBatch] All " << prepared.size() << " classes redefined in single pass" << std::endl;
    return JNIHOOK_OK;
}
