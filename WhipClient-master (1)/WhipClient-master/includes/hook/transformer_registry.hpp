#pragma once

#include <jni.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include "embedded_transformer.hpp"
#include "embedded_asm.hpp"
#include "handler/MappingHandler.h"
#include "util/Debug.h"
#include "util/MinecraftDetails.h"

class TransformerRegistry {
public:
    static bool Initialize(JNIEnv* env) {
        if (s_Initialized) return true;

        jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
        if (!classLoaderClass) {
            return false;
        }

        jmethodID getSystemClassLoader = env->GetStaticMethodID(classLoaderClass, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        jmethodID loadClass = env->GetMethodID(classLoaderClass, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (!getSystemClassLoader || !loadClass) {
            return false;
        }

        jobject systemClassLoader = env->CallStaticObjectMethod(classLoaderClass, getSystemClassLoader);

        jobject gameClassLoader = Mappings::getInstance().getGameClassLoader();

        // If game classloader not cached, try current thread's context classloader
        if (!gameClassLoader) {
            jclass threadCls = env->FindClass("java/lang/Thread");
            if (threadCls) {
                jmethodID ctMid  = env->GetStaticMethodID(threadCls, "currentThread", "()Ljava/lang/Thread;");
                jmethodID gclMid = env->GetMethodID(threadCls, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
                if (ctMid && gclMid) {
                    jobject t = env->CallStaticObjectMethod(threadCls, ctMid);
                    if (t) { gameClassLoader = env->CallObjectMethod(t, gclMid); env->DeleteLocalRef(t); }
                }
                env->DeleteLocalRef(threadCls);
                if (env->ExceptionCheck()) env->ExceptionClear();
            }
        }
        jobject effectiveLoader = gameClassLoader ? gameClassLoader : systemClassLoader;

        auto findClassInLoader = [&](const char* slashName) -> jclass {
            std::string dotted = slashName;
            for (char& c : dotted) if (c == '/') c = '.';
            jstring jname = env->NewStringUTF(dotted.c_str());
            jclass cls = static_cast<jclass>(env->CallObjectMethod(effectiveLoader, loadClass, jname));
            env->DeleteLocalRef(jname);
            if (!cls && env->ExceptionCheck()) env->ExceptionClear();
            return cls;
        };

        // Check that ALL required ASM classes are present, including AnnotationWriter
        // which is an internal class used by ClassWriter but not always bundled by launchers.
        bool asmAlreadyPresent = false;
        {
            jclass c1 = findClassInLoader("org/objectweb/asm/ClassReader");
            jclass c2 = findClassInLoader("org/objectweb/asm/AnnotationWriter");
            jclass c3 = findClassInLoader("org/objectweb/asm/commons/AdviceAdapter");
            if (c1) env->DeleteLocalRef(c1);
            if (c2) env->DeleteLocalRef(c2);
            if (c3) env->DeleteLocalRef(c3);
            asmAlreadyPresent = (c1 != nullptr) && (c2 != nullptr) && (c3 != nullptr);
        }

        if (!asmAlreadyPresent) {
            size_t cbAsmDefined = 0;
            size_t cbAsmAlready = 0;
            std::vector<size_t> pending;
            pending.reserve(EmbeddedAsm::CLASS_COUNT);
            for (size_t i = 0; i < EmbeddedAsm::CLASS_COUNT; ++i) pending.push_back(i);

            std::vector<std::string> lastErr(EmbeddedAsm::CLASS_COUNT);

            auto captureAndClearException = [&](size_t idx) {
                if (!env->ExceptionCheck()) return;
                jthrowable t = env->ExceptionOccurred();
                env->ExceptionClear();
                if (!t) return;
                jclass tClass = env->GetObjectClass(t);
                jmethodID toString = env->GetMethodID(tClass, "toString", "()Ljava/lang/String;");
                if (toString) {
                    jstring js = (jstring)env->CallObjectMethod(t, toString);
                    if (js) {
                        const char* c = env->GetStringUTFChars(js, nullptr);
                        if (c) {
                            lastErr[idx] = c;
                            env->ReleaseStringUTFChars(js, c);
                        }
                        env->DeleteLocalRef(js);
                    }
                    if (env->ExceptionCheck()) env->ExceptionClear();
                }
                env->DeleteLocalRef(tClass);
                env->DeleteLocalRef(t);
            };

            for (int pass = 0; !pending.empty() && pass < 16; ++pass) {
                std::vector<size_t> next;
                next.reserve(pending.size());
                bool progress = false;
                for (size_t idx : pending) {
                    const auto& e = EmbeddedAsm::CLASSES[idx];
                    jclass defined = env->DefineClass(
                        e.name,
                        effectiveLoader,
                        reinterpret_cast<const jbyte*>(e.data),
                        static_cast<jsize>(e.size)
                    );
                    if (defined) {
                        env->DeleteLocalRef(defined);
                        ++cbAsmDefined;
                        progress = true;
                        continue;
                    }
                    captureAndClearException(idx);

                    if (findClassInLoader(e.name)) {
                        ++cbAsmAlready;
                        progress = true;
                    } else {
                        next.push_back(idx);
                    }
                }
                pending = std::move(next);
                if (!progress) break;
            }

            if (!pending.empty()) {
                for (size_t idx : pending) {
                    std::cerr << "[TransformerRegistry] ASM class FAILED: "
                              << EmbeddedAsm::CLASSES[idx].name
                              << " err=" << (lastErr[idx].empty() ? "none" : lastErr[idx]) << std::endl;
                }
                return false;
            }
        }

        struct EmbeddedClass {
            const char* name;
            const uint8_t* data;
            size_t size;
        };

        std::vector<EmbeddedClass> customClasses = {
            {"org.apache.commons.internal.DispatcherTransformer", EmbeddedTransformer::DISPATCHER_TRANSFORMER, EmbeddedTransformer::DISPATCHER_TRANSFORMER_SIZE},
            {"org.apache.commons.internal.DispatcherTransformer$CustomClassWriter", EmbeddedTransformer::DISPATCHER_TRANSFORMER_CUSTOMCLASSWRITER, EmbeddedTransformer::DISPATCHER_TRANSFORMER_CUSTOMCLASSWRITER_SIZE},
            {"org.apache.commons.internal.DispatcherTransformer$HookMethodVisitor", EmbeddedTransformer::DISPATCHER_TRANSFORMER_HOOKMETHODVISITOR, EmbeddedTransformer::DISPATCHER_TRANSFORMER_HOOKMETHODVISITOR_SIZE},
            {"org.apache.commons.internal.DispatcherTransformer$InlineHookMethodVisitor", EmbeddedTransformer::DISPATCHER_TRANSFORMER_INLINEHOOKMETHODVISITOR, EmbeddedTransformer::DISPATCHER_TRANSFORMER_INLINEHOOKMETHODVISITOR_SIZE},
            {"org.apache.commons.internal.DispatcherTransformer$1", EmbeddedTransformer::DISPATCHER_TRANSFORMER_1, EmbeddedTransformer::DISPATCHER_TRANSFORMER_1_SIZE}
        };

        const auto launcher = MinecraftSession::getInstance().launcher;

        const bool useAsm9 = (launcher == MinecraftLauncher::L_LUNAR ||
                              launcher == MinecraftLauncher::L_MENORIA ||
                              launcher == MinecraftLauncher::L_CHEATBREAKER);
        const uint8_t targetAsmApiByte = useAsm9 ? 0x09 : 0x05;

        // The embedded DispatcherTransformer is compiled with `new ClassVisitor(Opcodes.ASM9, ...)`,
        // so its constant pool holds the CONSTANT_Integer for ASM9 (0x00090000): tag 0x03 + bytes 00 09 00 00.
        // On Lunar/Menoria/CheatBreaker (modern ASM) ASM9 is fine. On Forge/Badlion/Vanilla (Feather runs on
        // Forge 1.8.9 → ASM 5.0.3) the ClassVisitor ctor REJECTS ASM9 with IllegalArgumentException, killing
        // every transform. So we rewrite the baked-in api byte down to ASM5 for those hosts.
        // (Older builds searched for an ASM5 needle that no longer exists post-ASM9 bump → patch silently no-op'd.)
        bool asmPatchFound = false;
        auto patchAsmApi = [targetAsmApiByte, &asmPatchFound](const uint8_t* src, size_t size) -> std::vector<uint8_t> {
            std::vector<uint8_t> bytes(src, src + size);
            const uint8_t needle[5] = { 0x03, 0x00, 0x09, 0x00, 0x00 };
            for (size_t i = 0; i + sizeof(needle) <= bytes.size(); ++i) {
                if (std::memcmp(bytes.data() + i, needle, sizeof(needle)) == 0) {
                    bytes[i + 2] = targetAsmApiByte;
                    asmPatchFound = true;
                    break;
                }
            }
            return bytes;
        };

        std::vector<std::vector<uint8_t>> patchedBytes(customClasses.size());
        for (size_t i = 0; i < customClasses.size(); ++i) {
            const std::string idx = customClasses[i].name;
            const bool needsApiPatch =
                idx == "org.apache.commons.internal.DispatcherTransformer" ||
                idx == "org.apache.commons.internal.DispatcherTransformer$1";
            if (needsApiPatch) {
                patchedBytes[i] = patchAsmApi(customClasses[i].data, customClasses[i].size);
            }
        }
        for (size_t i = 0; i < customClasses.size(); ++i) {
            const auto& cls = customClasses[i];
            std::string slashName = cls.name;
            for (char& c : slashName) if (c == '.') c = '/';

            const uint8_t* defineData = patchedBytes[i].empty() ? cls.data : patchedBytes[i].data();
            jsize defineSize = patchedBytes[i].empty() ? static_cast<jsize>(cls.size) : static_cast<jsize>(patchedBytes[i].size());

            jclass definedClass = env->DefineClass(
                nullptr,
                effectiveLoader,
                reinterpret_cast<const jbyte*>(defineData),
                defineSize
            );

            if (!definedClass || env->ExceptionCheck()) {

                std::string defineExc;
                if (env->ExceptionCheck()) {
                    jthrowable t = env->ExceptionOccurred();
                    env->ExceptionClear();
                    if (t) {
                        jclass tClass = env->GetObjectClass(t);
                        if (tClass) {
                            jmethodID toString = env->GetMethodID(tClass, "toString", "()Ljava/lang/String;");
                            if (toString) {
                                jstring js = (jstring)env->CallObjectMethod(t, toString);
                                if (js) {
                                    const char* c = env->GetStringUTFChars(js, nullptr);
                                    if (c) { defineExc = c; env->ReleaseStringUTFChars(js, c); }
                                    env->DeleteLocalRef(js);
                                }
                                if (env->ExceptionCheck()) env->ExceptionClear();
                            }
                            env->DeleteLocalRef(tClass);
                        }
                        env->DeleteLocalRef(t);
                    }
                }

                jclass existing = findClassInLoader(slashName.c_str());
                if (!existing) {
                    std::cerr << "[TransformerRegistry] Failed to load class: " << cls.name
                              << " — DefineClass exception: "
                              << (defineExc.empty() ? "(unknown)" : defineExc) << std::endl;
                    return false;
                }
                if (patchedBytes[i].empty()) {
                } else {

                    std::cerr << "[TransformerRegistry] STALE CLASS: " << cls.name
                              << " was already defined by a previous injection (the host JVM was"
                              << " not restarted) — DefineClass got: "
                              << (defineExc.empty() ? "LinkageError" : defineExc)
                              << ". The patched ASM-api bytes will NOT take effect; the existing"
                              << " class is being used as-is. To apply the fix, fully quit the"
                              << " launcher (Lunar Client / Badlion Client / etc.) AND kill any"
                              << " surviving javaw.exe / java.exe before relaunching."
                              << std::endl;
                }
            } else {
            }
        }

        jclass transformerClass = findClassInLoader("org/apache/commons/internal/DispatcherTransformer");
        if (!transformerClass) {
            return false;
        }

        s_TransformerClass = (jclass)env->NewGlobalRef(transformerClass);

        s_TransformMethod = env->GetStaticMethodID(
            s_TransformerClass,
            "transform",
            "([BLjava/lang/String;Ljava/lang/String;I)[B"
        );

        if (!s_TransformMethod) {
            return false;
        }

        {
            jclass baosClass = env->FindClass("java/io/ByteArrayOutputStream");
            jclass printStreamClass = env->FindClass("java/io/PrintStream");
            jclass systemClass = env->FindClass("java/lang/System");
            if (baosClass && printStreamClass && systemClass) {
                jmethodID baosCtor = env->GetMethodID(baosClass, "<init>", "()V");
                jmethodID psCtor = env->GetMethodID(printStreamClass, "<init>", "(Ljava/io/OutputStream;Z)V");
                jmethodID setErr = env->GetStaticMethodID(systemClass, "setErr", "(Ljava/io/PrintStream;)V");
                if (baosCtor && psCtor && setErr) {
                    jobject baos = env->NewObject(baosClass, baosCtor);
                    if (baos) {
                        jobject ps = env->NewObject(printStreamClass, psCtor, baos, JNI_TRUE);
                        if (ps) {
                            env->CallStaticVoidMethod(systemClass, setErr, ps);
                            if (env->ExceptionCheck()) env->ExceptionClear();
                            s_StderrCapture = env->NewGlobalRef(baos);
                            env->DeleteLocalRef(ps);
                        }
                        env->DeleteLocalRef(baos);
                    }
                }
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }

        s_Initialized = true;
        return true;
    }

    static void Shutdown(JNIEnv* env) {
        if (!s_Initialized) return;

        if (s_TransformerClass && env) {
            env->DeleteGlobalRef(s_TransformerClass);
            s_TransformerClass = nullptr;
        }
        s_TransformMethod = nullptr;
        s_Initialized = false;
    }

    static std::vector<uint8_t> Transform(JNIEnv* env, const std::vector<uint8_t>& classBytes, const std::string& methodName, const std::string& methodDesc, int hookId) {
        if (!s_Initialized || !s_TransformMethod) return {};
        if (classBytes.empty()) return {};

        jbyteArray javaBytes = env->NewByteArray((jsize)classBytes.size());
        if (!javaBytes) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            return {};
        }

        // Patch class file major version to 65 (Java 21) if higher.
        // ASM 9.6 (bundled by some launchers) throws "Unsupported class file major version N"
        // for Java 22+ class files (versions 66+). Java 25 VM runs Java 21 class files fine.
        {
            const uint8_t* src = classBytes.data();
            jsize sz = (jsize)classBytes.size();
            if (sz >= 8) {
                uint16_t majorVer = ((uint16_t)src[6] << 8) | (uint16_t)src[7];
                if (majorVer > 65) {
                    std::vector<uint8_t> patched(src, src + sz);
                    patched[6] = 0x00;
                    patched[7] = 0x41; // 65 = Java 21
                    env->SetByteArrayRegion(javaBytes, 0, sz, reinterpret_cast<const jbyte*>(patched.data()));
                } else {
                    env->SetByteArrayRegion(javaBytes, 0, sz, reinterpret_cast<const jbyte*>(src));
                }
            } else {
                env->SetByteArrayRegion(javaBytes, 0, (jsize)classBytes.size(), reinterpret_cast<const jbyte*>(classBytes.data()));
            }
        }

        jstring jMethodName = env->NewStringUTF(methodName.c_str());
        jstring jMethodDesc = env->NewStringUTF(methodDesc.c_str());

        // Set the thread's context classloader to the game classloader so that
        // CustomClassWriter.getCommonSuperClass() can resolve obfuscated types.
        // Without this, it falls back to java/lang/Object for every unresolvable type,
        // producing incorrect StackMapTable entries → JIT emits bad code → GC crash.
        jobject savedContextLoader = nullptr;
        jobject currentThread = nullptr;
        jmethodID setContextCLMid = nullptr;
        {
            jclass threadCls = env->FindClass("java/lang/Thread");
            if (threadCls && !env->ExceptionCheck()) {
                jmethodID currentThreadMid = env->GetStaticMethodID(threadCls, "currentThread", "()Ljava/lang/Thread;");
                jmethodID getContextCLMid  = env->GetMethodID(threadCls, "getContextClassLoader", "()Ljava/lang/ClassLoader;");
                setContextCLMid            = env->GetMethodID(threadCls, "setContextClassLoader", "(Ljava/lang/ClassLoader;)V");
                if (currentThreadMid && getContextCLMid && setContextCLMid) {
                    currentThread     = env->CallStaticObjectMethod(threadCls, currentThreadMid);
                    savedContextLoader = env->CallObjectMethod(currentThread, getContextCLMid);
                    jobject gameLoader = Mappings::getInstance().getGameClassLoader();
                    if (gameLoader && currentThread) {
                        env->CallVoidMethod(currentThread, setContextCLMid, gameLoader);
                        if (env->ExceptionCheck()) env->ExceptionClear();
                    }
                }
                env->DeleteLocalRef(threadCls);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }

        jobject resultObj = env->CallStaticObjectMethod(s_TransformerClass, s_TransformMethod, javaBytes, jMethodName, jMethodDesc, hookId);

        // IMPORTANT: save any pending exception from transform() BEFORE
        // the classloader restoration calls (which would clear it via ExceptionClear).
        jthrowable transformThrowable = nullptr;
        if (env->ExceptionCheck()) {
            transformThrowable = env->ExceptionOccurred();
            env->ExceptionClear();
        }

        // Restore original context classloader
        if (currentThread && setContextCLMid) {
            env->CallVoidMethod(currentThread, setContextCLMid, savedContextLoader);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (currentThread)      env->DeleteLocalRef(currentThread);
        if (savedContextLoader) env->DeleteLocalRef(savedContextLoader);

        // Re-throw the transform exception so the error path below prints it
        if (transformThrowable) {
            env->Throw(transformThrowable);
            env->DeleteLocalRef(transformThrowable);
        }

        if (env->ExceptionCheck()) {
            jthrowable t = env->ExceptionOccurred();
            env->ExceptionClear();
            std::string msg = "(could not extract message)";
            if (t) {
                jclass tClass = env->GetObjectClass(t);
                if (tClass) {
                    jmethodID toString = env->GetMethodID(tClass, "toString", "()Ljava/lang/String;");
                    if (toString) {
                        jstring js = (jstring)env->CallObjectMethod(t, toString);
                        if (js) {
                            const char* c = env->GetStringUTFChars(js, nullptr);
                            if (c) { msg = c; env->ReleaseStringUTFChars(js, c); }
                            env->DeleteLocalRef(js);
                        }
                        if (env->ExceptionCheck()) env->ExceptionClear();
                    }
                    env->DeleteLocalRef(tClass);
                }
                env->DeleteLocalRef(t);
            }
            std::cerr << "[TransformerRegistry] Transform threw for " << methodName << methodDesc
                      << " (hookId=" << hookId << "): " << msg << std::endl;
            std::string capturedErr = DrainCapturedStderr(env);
            if (!capturedErr.empty()) {
                std::cerr << "[TransformerRegistry] Captured stderr from transform:\n" << capturedErr << std::endl;
            }
            return {};
        }

        if (!resultObj) {
            std::string capturedErr = DrainCapturedStderr(env);
            std::cerr << "[TransformerRegistry] Transform returned null for " << methodName << methodDesc
                      << " (hookId=" << hookId << ")" << std::endl;
            if (!capturedErr.empty()) {
                std::cerr << "[TransformerRegistry] Captured stderr from transform:\n" << capturedErr << std::endl;
            } else {
                std::cerr << "[TransformerRegistry] (no stderr captured)" << std::endl;
            }
            return {};
        }

        jbyteArray resultBytes = (jbyteArray)resultObj;
        jsize length = env->GetArrayLength(resultBytes);

        if (length == 0) {
            std::string capturedErr = DrainCapturedStderr(env);
            std::cerr << "[TransformerRegistry] Transform returned 0-length array for " << methodName << methodDesc
                      << " (hookId=" << hookId << ")" << std::endl;
            if (!capturedErr.empty()) {
                std::cerr << "[TransformerRegistry] Captured stderr from transform:\n" << capturedErr << std::endl;
            }
        }

        std::vector<uint8_t> output(length);
        env->GetByteArrayRegion(resultBytes, 0, length, reinterpret_cast<jbyte*>(output.data()));

        return output;
    }

private:
    inline static bool s_Initialized = false;
    inline static jclass s_TransformerClass = nullptr;
    inline static jmethodID s_TransformMethod = nullptr;
    inline static jobject s_StderrCapture = nullptr;

    static std::string DrainCapturedStderr(JNIEnv* env) {
        if (!s_StderrCapture) return {};
        jclass baosClass = env->GetObjectClass(s_StderrCapture);
        if (!baosClass) return {};
        jmethodID toStringM = env->GetMethodID(baosClass, "toString", "()Ljava/lang/String;");
        jmethodID resetM = env->GetMethodID(baosClass, "reset", "()V");
        std::string out;
        if (toStringM) {
            jstring js = (jstring)env->CallObjectMethod(s_StderrCapture, toStringM);
            if (js) {
                const char* c = env->GetStringUTFChars(js, nullptr);
                if (c) { out = c; env->ReleaseStringUTFChars(js, c); }
                env->DeleteLocalRef(js);
            }
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        if (resetM) {
            env->CallVoidMethod(s_StderrCapture, resetM);
            if (env->ExceptionCheck()) env->ExceptionClear();
        }
        env->DeleteLocalRef(baosClass);
        return out;
    }
};
