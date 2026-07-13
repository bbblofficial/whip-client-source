#pragma once

#ifndef MAIN_H
#define MAIN_H

#define _WINSOCKAPI_

#ifdef _DEBUG
#include "../includes/util/MemoryDebug.h"
#endif

#include "../includes/auth/service/WhipAuthService.h"
#include "../includes/gui/Gui.h"
#include "../includes/util/debug.h"
#include "../includes/handler/VersionHandler.h"
#include "handler/MappingHandler.h"
#include "../includes/wrapper/primitive/javaobject.h"
#include "../includes/handler/TaskHandler.h"
#include "../includes/task/impl/InputTask.h"
#include "../includes/task/impl/UpdateTask.h"
#include "../includes/util/minecraftdetails.h"
#include "../includes/util/JniScope.h"

#ifdef VMP
#include "VMProtectSDK.h"
#endif

#endif MAIN_H
