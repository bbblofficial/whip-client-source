#pragma optimize("", off)
#include "loader/Loader.h"

void Loader::stepValidateLicense() {
    transitionTo(LoaderStep::DownloadingModule, "Downloading module...");
}
#pragma optimize("", on)
