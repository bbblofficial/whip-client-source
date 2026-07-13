#include "../../includes/handler/VersionHandler.h"
#include "../../includes/util/whipJson.h"
#include <iostream>
#include <cstring>
#include <fstream>
#include <cstdio>
#include <cstdlib>
#include <windows.h>

#include "util/Debug.h"
#include "util/JNIUtils.h"

namespace {

    bool cmdlineMatchesAllTokens(const char* cmdline, const char* requirements) {
        if (!cmdline || !requirements || !*requirements) return false;
        const char* p = requirements;
        while (*p) {
            while (*p == ' ' || *p == '\t') ++p;
            if (!*p) break;
            const char* start = p;
            while (*p && *p != ' ' && *p != '\t') ++p;
            std::string token(start, p - start);
            if (!token.empty() && !strstr(cmdline, token.c_str())) return false;
        }
        return true;
    }
}

VersionHandler::VersionHandler() {
}

char* createCString(const char* source) {
    if (!source) return nullptr;
    size_t len = strlen(source);
    char* copy = new char[len + 1];
    strcpy(copy, source);
    return copy;
}

char* concatenateStrings(const char* str1, const char* str2) {
    if (!str1 || !str2) return nullptr;
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);
    char* result = new char[len1 + len2 + 1];
    strcpy(result, str1);
    strcat(result, str2);
    return result;
}

char* intToString(int value) {
    char* buffer = new char[32];
    sprintf(buffer, "%d", value);
    return buffer;
}

void VersionHandler::registerVersion(Version version) {
    versions.push_back(version);
}

bool VersionHandler::parseAndRegisterVersions(const char* versionsData, size_t dataSize) {

    if (!versionsData || dataSize == 0) {
        return false;
    }

    clearVersions();

    try {
        char* jsonBuffer = new char[dataSize + 1];
        memcpy(jsonBuffer, versionsData, dataSize);
        jsonBuffer[dataSize] = '\0';

        char previewBuffer[105];
        size_t previewLen = (dataSize > 100) ? 100 : dataSize;
        memcpy(previewBuffer, jsonBuffer, previewLen);
        previewBuffer[previewLen] = '\0';

        whip::WhipJsonValue versionsJson = whip::WhipJsonValue::parse(jsonBuffer);
        delete[] jsonBuffer;

        if (!versionsJson.is_array()) {
            return false;
        }

        for (const auto& versionJson : versionsJson) {
            Version version = {};

            version.versionKey = versionJson["versionKey"].get<int>();

            std::string minecraftClassStr = versionJson["minecraftClass"].get<std::string>();
            version.minecraftClass = createCString(minecraftClassStr.c_str());

            std::string theMinecraftFieldStr = versionJson["theMinecraftField"].get<std::string>();
            version.theMinecraftField = createCString(theMinecraftFieldStr.c_str());

            std::string launchedVersionFieldStr = versionJson["launchedVersionField"].get<std::string>();
            version.launchedVersionField = createCString(launchedVersionFieldStr.c_str());

            std::string launchedVersionValueStr = versionJson["launchedVersionValue"].get<std::string>();
            version.launchedVersionValue = createCString(launchedVersionValueStr.c_str());

            version.minecraftVersion = static_cast<MinecraftVersion>(versionJson["minecraftVersion"].get<int>());
            version.minecraftLauncher = static_cast<MinecraftLauncher>(versionJson["minecraftLauncher"].get<int>());
            version.classResolvingMethod = static_cast<ClassResolvingMethod>(versionJson["classResolvingMethod"].get<int>());

            std::string specificClassLoaderClassStr = versionJson["specificClassLoaderClass"].get<std::string>();
            if (!specificClassLoaderClassStr.empty()) {
                version.specificClassLoaderClass = createCString(specificClassLoaderClassStr.c_str());
            } else {
                version.specificClassLoaderClass = nullptr;
            }

            std::string specificClassLoaderFieldStr = versionJson["specificClassLoaderField"].get<std::string>();
            if (!specificClassLoaderFieldStr.empty()) {
                version.specificClassLoaderField = createCString(specificClassLoaderFieldStr.c_str());
            } else {
                version.specificClassLoaderField = nullptr;
            }

            std::string specificClassLoaderSigStr = versionJson["specificClassLoaderSig"].get<std::string>();
            if (!specificClassLoaderSigStr.empty()) {
                version.specificClassLoaderSig = createCString(specificClassLoaderSigStr.c_str());
            } else {
                version.specificClassLoaderSig = nullptr;
            }

            if (versionJson.contains("cmdlineRequired")) {
                std::string cmdlineRequiredStr = versionJson["cmdlineRequired"].get<std::string>();
                version.cmdlineRequired = cmdlineRequiredStr.empty()
                        ? nullptr
                        : createCString(cmdlineRequiredStr.c_str());
            } else {
                version.cmdlineRequired = nullptr;
            }

            registerVersion(version);
        }

        return true;

    } catch (const std::exception&) {
        return false;
    }
}

bool VersionHandler::findVersion(JNIEnv* env, Version* foundVersion) {

    const char* cmdline = GetCommandLineA();

    for (auto& version : this->versions) {

        if (version.cmdlineRequired && *version.cmdlineRequired) {
            if (!cmdline) continue;
            if (!cmdlineMatchesAllTokens(cmdline, version.cmdlineRequired)) continue;
            if (version.launchedVersionValue && *version.launchedVersionValue
                    && !strstr(cmdline, version.launchedVersionValue)) {
                continue;
            }
            *foundVersion = version;
            return true;
        }

        jclass mcClass = nullptr;

        if (version.classResolvingMethod == ClassResolvingMethod::ROOT_CLASSLOADER) {
            mcClass = env->FindClass(version.minecraftClass);
            if (!mcClass && env->ExceptionCheck()) env->ExceptionClear();
        }
        else if (version.classResolvingMethod == ClassResolvingMethod::SPECIFIC_CLASSLOADER) {

            bool hasSpecificClassLoader = (version.specificClassLoaderClass &&
                                         strlen(version.specificClassLoaderClass) > 0 &&
                                         version.specificClassLoaderField &&
                                         strlen(version.specificClassLoaderField) > 0 &&
                                         version.specificClassLoaderSig &&
                                         strlen(version.specificClassLoaderSig) > 0);

            if (hasSpecificClassLoader) {
                jclass classLoaderClass = env->FindClass("java/lang/ClassLoader");
                if (classLoaderClass) {
                    jmethodID findClassMethod = env->GetMethodID(classLoaderClass, "findClass", "(Ljava/lang/String;)Ljava/lang/Class;");
                    if (findClassMethod) {
                        jclass clsClass = env->FindClass(version.specificClassLoaderClass);
                        if (clsClass) {
                            jfieldID clsField = env->GetStaticFieldID(clsClass, version.specificClassLoaderField, version.specificClassLoaderSig);
                            jobject gameClassloader = clsField ? env->GetStaticObjectField(clsClass, clsField) : nullptr;
                            if (gameClassloader) {
                                jstring sName = (jstring)env->NewStringUTF(version.minecraftClass);
                                mcClass = (jclass)env->CallObjectMethod(gameClassloader, findClassMethod, sName);
                                env->DeleteLocalRef(sName);
                                if (!mcClass && env->ExceptionCheck()) env->ExceptionClear();
                            }
                        } else {
                            if (env->ExceptionCheck()) env->ExceptionClear();
                        }
                    }
                }
            } else {
                mcClass = findClassWithThreads(env, version.minecraftClass);
            }
        }
        else if (version.classResolvingMethod == ClassResolvingMethod::THREADS_CLASSLOADER) {
            mcClass = findClassWithThreads(env, version.minecraftClass);
        }
        else if (version.classResolvingMethod == ClassResolvingMethod::DISCOVERED_CLASSLOADER) {

            mcClass = findClassViaJvmti(env, version.minecraftClass);
            if (!mcClass && env->ExceptionCheck()) env->ExceptionClear();
        }

        if (!mcClass) {
            continue;
        }

        size_t mcClassLen = strlen(version.minecraftClass);
        char* theMCSig = new char[mcClassLen + 3];
        memset(theMCSig, 0, mcClassLen + 3);
        theMCSig[0] = 'L';
        theMCSig[mcClassLen + 1] = ';';
        memcpy(theMCSig + 1, version.minecraftClass, mcClassLen);

        jfieldID theMCField = env->GetStaticFieldID(mcClass, version.theMinecraftField, theMCSig);
        delete[] theMCSig;

        if (!theMCField) {
            if (env->ExceptionCheck()) env->ExceptionClear();
            continue;
        }

        jobject theMC = env->GetStaticObjectField(mcClass, theMCField);
        if (!theMC) {
            continue;
        }

        if (version.launchedVersionField) {

            jfieldID mcVersionField = env->GetFieldID(mcClass, version.launchedVersionField, "Ljava/lang/String;");
            if (!mcVersionField) {
                if (env->ExceptionCheck()) env->ExceptionClear();
                continue;
            }

            jstring mcVersion = (jstring)env->GetObjectField(theMC, mcVersionField);
            if (!mcVersion) {
                continue;
            }

            if (version.launchedVersionValue) {

                const char* _mcVersion = env->GetStringUTFChars(mcVersion, 0);
                if (!_mcVersion) {
                    continue;
                }

                size_t targetVersionLength = strlen(version.launchedVersionValue);
                if (strlen(_mcVersion) < targetVersionLength ||
                    memcmp(_mcVersion, version.launchedVersionValue, targetVersionLength)) {
                    env->ReleaseStringUTFChars(mcVersion, _mcVersion);
                    continue;
                }
                env->ReleaseStringUTFChars(mcVersion, _mcVersion);
            }
        }

        *foundVersion = version;
        return true;
    }

    return false;
}

void VersionHandler::clearVersions() {
    for (const Version& version : versions) {
        delete[] version.minecraftClass;
        delete[] version.theMinecraftField;
        delete[] version.launchedVersionField;
        delete[] version.launchedVersionValue;
        delete[] version.specificClassLoaderClass;
        delete[] version.specificClassLoaderField;
        delete[] version.specificClassLoaderSig;
        delete[] version.cmdlineRequired;
    }
    versions.clear();
}

VersionHandler& VersionHandler::getInstance() {
    static VersionHandler instance;
    return instance;
}
