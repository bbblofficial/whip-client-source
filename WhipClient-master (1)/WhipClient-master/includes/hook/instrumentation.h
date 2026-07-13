#ifndef _JNI_INSTRUMENTS_BACKEND_H_
#define _JNI_INSTRUMENTS_BACKEND_H_

#include <jni.h>
#include <jvmti.h>
#include <functional>
#include <vector>
#include <string>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

	typedef enum {
		JNIHOOK_OK = 0,
		JNIHOOK_ERR_GET_JNI,
		JNIHOOK_ERR_GET_JVMTI,
		JNIHOOK_ERR_ADD_JVMTI_CAPS,
		JNIHOOK_ERR_SETUP_CLASS_FILE_LOAD_HOOK,
		JNIHOOK_ERR_JNI_OPERATION,
		JNIHOOK_ERR_JVMTI_OPERATION,
		JNIHOOK_ERR_CLASS_FILE_CACHE,
	} jnihook_result_t;

#ifdef __cplusplus
}
#endif

using InstrumentRawCallback = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&, const std::string&, const std::string&)>;

class JvmInstrumentor {
public:
	static JvmInstrumentor& Get();

	JvmInstrumentor(const JvmInstrumentor&) = delete;
	JvmInstrumentor& operator=(const JvmInstrumentor&) = delete;

	bool Initialize(JavaVM* vm);

	bool Shutdown();

	void RevertAll(jobject classLoader = nullptr);

	bool RestoreClass(const std::string& className);

	jnihook_result_t Instrument(jmethodID method, InstrumentRawCallback callback);

	struct BatchEntry {
		jmethodID method;
		InstrumentRawCallback callback;
	};
	jnihook_result_t InstrumentBatch(const std::vector<BatchEntry>& entries);

	JavaVM* GetJvm() const { return m_Jvm; }
	jvmtiEnv* GetJvmti() const { return m_Jvmti; }

private:
	JvmInstrumentor() = default;
	~JvmInstrumentor() = default;

	JavaVM* m_Jvm = nullptr;
	jvmtiEnv* m_Jvmti = nullptr;
	bool m_Initialized = false;
};

#endif
