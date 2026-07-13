#include "../../../../../includes/wrapper/minecraft/client/settings/KeyBinding.h"

jfieldID  KeyBinding::pressedId          = nullptr;
jfieldID  KeyBinding::pressTimeId        = nullptr;
jfieldID  KeyBinding::keyCodeId          = nullptr;
jclass    KeyBinding::lwjglKeyboardClass_ = nullptr;
jmethodID KeyBinding::isKeyDownMethodId_ = nullptr;
