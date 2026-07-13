#include "../../includes/setting/Setting.h"
#include "../../includes/manager/ConfigManager.h"

void BoolSetting::setValue(const bool value) const {
    bool oldValue = *m_value;
    *m_value = value;

    if (m_callback && oldValue != value && !ConfigManager::getInstance().isLoadingConfig()) {
        m_callback(value);
    }
}
