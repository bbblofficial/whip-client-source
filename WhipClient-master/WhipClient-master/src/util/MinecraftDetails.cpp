#include "../../includes/util/MinecraftDetails.h"

MinecraftSession& MinecraftSession::getInstance() {
    static MinecraftSession instance;
    return instance;
}
