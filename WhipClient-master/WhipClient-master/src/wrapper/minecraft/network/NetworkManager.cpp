#include "../../../../includes/wrapper/minecraft/network/NetworkManager.h"

jmethodID NetworkManager::sendPacketId = nullptr;
jmethodID NetworkManager::isChannelOpenId = nullptr;
jmethodID NetworkManager::closeChannelId = nullptr;
jmethodID NetworkManager::processReceivedPacketsId = nullptr;
jmethodID NetworkManager::channelRead0Id = nullptr;
jmethodID NetworkManager::dispatchPacketId = nullptr;
jfieldID NetworkManager::netHandlerId = nullptr;
jfieldID NetworkManager::packetListenerId = nullptr;
