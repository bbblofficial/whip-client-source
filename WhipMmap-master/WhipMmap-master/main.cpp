#include <iostream>

#include "include/ManualMapper/ManualMapper.h"

int main()
{
    ManualMapper::ManualMapper mapper;

    std::wstring dllPath = L"D:\\all\\whip\\dll.dll";
    std::wstring targetProcess = L"javaw.exe";

    if (!mapper.LoadImage(dllPath))
    {
        return 1;
    }

    int mode = 0;
    std::cin >> mode;
    std::cin.ignore();

    if (mode == 2)
    {

        if (!mapper.ScatterMapToProcess(targetProcess))
        {
            return 1;
        }

        if (!mapper.ExecuteScattered())
        {
            return 1;
        }

        std::cin.get();

        if (!mapper.UnloadScattered())
        {
            return 1;
        }

    }
    else
    {

        if (!mapper.MapToProcess(targetProcess))
        {
            return 1;
        }

        if (!mapper.Execute())
        {
            return 1;
        }

        std::cin.get();

        if (!mapper.Unload())
        {
            return 1;
        }

    }

    return 0;
}
