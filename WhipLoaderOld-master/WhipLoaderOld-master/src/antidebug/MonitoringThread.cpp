#include "antidebug/common.h"
#include "antidebug/SecurityHelper.h"
#include "antidebug/MonitoringThread.h"
#include "auth/auth.h"

DWORD WINAPI BackgroundMonitoringThread(LPVOID lpParam)
{
    Security security;
    security.AntiAttach();

    Auth* auth = Auth::getInstance();

    static int fast_check_count = 0;
    static int heavy_check_count = 0;
    static int cycle_count = 0;

    while (TRUE)
    {
        cycle_count++;
        fast_check_count++;

        if (security.IsBeingDebugged()) {
            if (auth && auth->getHwid()) {
                auth->reportThreat("debugger_multiple", "Multiple debugger detection techniques triggered");
            } else {
            }

            TerminateProcess(GetCurrentProcess(), 1);
        }

        if (security.HasHooks()) {

            if (auth && auth->getHwid()) {
                auth->reportThreat("api_hooks", "API hooking detected on critical functions");
            } else {
            }

            TerminateProcess(GetCurrentProcess(), 1);
        }

        if (security.IsOnVM()) {

            if (auth && auth->getHwid()) {
                auth->reportThreat("virtual_machine", "Virtual machine or sandbox environment detected");
            } else {
            }

            TerminateProcess(GetCurrentProcess(), 1);
        }

        security.exe_detect();
        security.title_detect();

        if (cycle_count % 2 == 0) {
            heavy_check_count++;

            if (ENABLE_DEBUG_CHECKS) {
                exec_check_silent(&IsDebuggerPresentAPI, TEXT("Checking IsDebuggerPresent API"));
                exec_check_silent(&IsDebuggerPresentPEB, TEXT("Checking PEB.BeingDebugged"));
                exec_check_silent(&CheckRemoteDebuggerPresentAPI, TEXT("Checking CheckRemoteDebuggerPresent API"));
                exec_check_silent(&NtGlobalFlag, TEXT("Checking PEB.NtGlobalFlag"));
                exec_check_silent(&HeapFlags, TEXT("Checking ProcessHeap.Flags"));
                exec_check_silent(&HeapForceFlags, TEXT("Checking ProcessHeap.ForceFlags"));
                exec_check_silent(&NtQueryInformationProcess_ProcessDebugPort, TEXT("Checking NtQueryInformationProcess with ProcessDebugPort"));
                exec_check_silent(&NtQueryInformationProcess_ProcessDebugFlags, TEXT("Checking NtQueryInformationProcess with ProcessDebugFlags"));
                exec_check_silent(&NtQueryInformationProcess_ProcessDebugObject, TEXT("Checking NtQueryInformationProcess with ProcessDebugObject"));
                exec_check_silent(&WUDF_IsAnyDebuggerPresent, TEXT("Checking WudfIsAnyDebuggerPresent API"));
                exec_check_silent(&WUDF_IsKernelDebuggerPresent, TEXT("Checking WudfIsKernelDebuggerPresent API"));
                exec_check_silent(&WUDF_IsUserDebuggerPresent, TEXT("Checking WudfIsUserDebuggerPresent API"));
                exec_check_silent(&NtSetInformationThread_ThreadHideFromDebugger, TEXT("Checking NtSetInformationThread with ThreadHideFromDebugger"));
                exec_check_silent(&CloseHandle_InvalideHandle, TEXT("Checking CloseHandle with an invalide handle"));
                exec_check_silent(&NtSystemDebugControl_Command, TEXT("Checking NtSystemDebugControl"));
                exec_check_silent(&UnhandledExcepFilterTest, TEXT("Checking UnhandledExcepFilterTest"));
                exec_check_silent(&OutputDebugStringAPI, TEXT("Checking OutputDebugString"));
                exec_check_silent(&HardwareBreakpoints, TEXT("Checking Hardware Breakpoints"));
                exec_check_silent(&Interrupt_0x2d, TEXT("Checking Interupt 0x2d"));
                exec_check_silent(&Interrupt_3, TEXT("Checking Interupt 1"));
                exec_check_silent(&TrapFlag, TEXT("Checking trap flag"));
                exec_check_silent(&MemoryBreakpoints_PageGuard, TEXT("Checking Memory Breakpoints PAGE GUARD"));
                exec_check_silent(&CanOpenCsrss, TEXT("Checking SeDebugPrivilege"));
                exec_check_silent(&NtQueryObject_ObjectTypeInformation, TEXT("Checking NtQueryObject with ObjectTypeInformation"));
                exec_check_silent(&NtQueryObject_ObjectAllTypesInformation, TEXT("Checking NtQueryObject with ObjectAllTypesInformation"));
                exec_check_silent(&NtYieldExecutionAPI, TEXT("Checking NtYieldExecution"));
                exec_check_silent(&SetHandleInformatiom_ProtectedHandle, TEXT("Checking CloseHandle protected handle trick"));
                exec_check_silent(&NtQuerySystemInformation_SystemKernelDebuggerInformation, TEXT("Checking NtQuerySystemInformation with SystemKernelDebuggerInformation"));
                exec_check_silent(&SharedUserData_KernelDebugger, TEXT("Checking SharedUserData->KdDebuggerEnabled"));
                exec_check_silent(&ProcessJob, TEXT("Checking if process is in a job"));
                exec_check_silent(&VirtualAlloc_WriteWatch_BufferOnly, TEXT("Checking VirtualAlloc write watch (buffer only)"));
                exec_check_silent(&VirtualAlloc_WriteWatch_APICalls, TEXT("Checking VirtualAlloc write watch (API calls)"));
                exec_check_silent(&VirtualAlloc_WriteWatch_IsDebuggerPresent, TEXT("Checking VirtualAlloc write watch (IsDebuggerPresent)"));
                exec_check_silent(&VirtualAlloc_WriteWatch_CodeWrite, TEXT("Checking VirtualAlloc write watch (code write)"));
                exec_check_silent(&PageExceptionBreakpointCheck, TEXT("Checking for page exception breakpoints"));
                exec_check_silent(&ModuleBoundsHookCheck, TEXT("Checking for API hooks outside module bounds"));
            }

            if (ENABLE_GEN_SANDBOX_CHECKS) {
                exec_check_silent(&NumberOfProcessors, TEXT("Checking Number of processors in machine"));
                exec_check_silent(&idt_trick, TEXT("Checking Interupt Descriptor Table location"));
                exec_check_silent(&ldt_trick, TEXT("Checking Local Descriptor Table location"));
                exec_check_silent(&gdt_trick, TEXT("Checking Global Descriptor Table location"));
                exec_check_silent(&str_trick, TEXT("Checking Store Task Register"));
                exec_check_silent(&number_cores_wmi, TEXT("Checking Number of cores in machine using WMI"));
                exec_check_silent(&disk_size_wmi, TEXT("Checking hard disk size using WMI"));
                exec_check_silent(&dizk_size_deviceiocontrol, TEXT("Checking hard disk size using DeviceIoControl"));
                exec_check_silent(&setupdi_diskdrive, TEXT("Checking SetupDi_diskdrive"));
                exec_check_silent(&memory_space, TEXT("Checking memory space using GlobalMemoryStatusEx"));
                exec_check_silent(&disk_size_getdiskfreespace, TEXT("Checking disk size using GetDiskFreeSpaceEx"));
                exec_check_silent(&cpuid_is_hypervisor, TEXT("Checking if CPU hypervisor field is set using cpuid(0x1)"));
                exec_check_silent(&cpuid_hypervisor_vendor, TEXT("Checking hypervisor vendor using cpuid(0x40000000)"));
                exec_check_silent(&hosting_check, TEXT("Check if Machine is hosted on Cloud"));
                exec_check_silent(&accelerated_sleep, TEXT("Check if time has been accelerated"));
                exec_check_silent(&serial_number_bios_wmi, TEXT("Checking SerialNumber from BIOS using WMI"));
                exec_check_silent(&model_computer_system_wmi, TEXT("Checking Model from ComputerSystem using WMI"));
                exec_check_silent(&manufacturer_computer_system_wmi, TEXT("Checking Manufacturer from ComputerSystem using WMI"));
                exec_check_silent(&current_temperature_acpi_wmi, TEXT("Checking Current Temperature using WMI"));
                exec_check_silent(&process_id_processor_wmi, TEXT("Checking ProcessId using WMI"));
                exec_check_silent(&power_capabilities, TEXT("Checking power capabilities"));
                exec_check_silent(&query_license_value, TEXT("Checking NtQueryLicenseValue with Kernel-VMDetection-Private"));
                exec_check_silent(&pirated_windows, TEXT("Checking if Windows is Genuine"));
                exec_check_silent(&registry_services_disk_enum, TEXT("Checking Services\\Disk\\Enum entries for VM strings"));
                exec_check_silent(&registry_disk_enum, TEXT("Checking Enum\\IDE and Enum\\SCSI entries for VM strings"));
                exec_check_silent(&number_SMBIOS_tables, TEXT("Checking SMBIOS tables"));
            }

            if (ENABLE_VBOX_CHECKS) {
                exec_check_silent(&vbox_dir, TEXT("Checking VirtualBox Guest Additions directory"));
                exec_check_silent(&vbox_check_mac, TEXT("Checking Mac Address start with 08:00:27"));
                exec_check_silent(&vbox_window_class, TEXT("Checking VBoxTrayToolWndClass / VBoxTrayToolWnd"));
                exec_check_silent(&vbox_network_share, TEXT("Checking VirtualBox Shared Folders network provider"));
                exec_check_silent(&vbox_pnpentity_pcideviceid_wmi, TEXT("Checking Win32_PnPDevice DeviceId from WMI for VBox PCI device"));
                exec_check_silent(&vbox_pnpentity_controllers_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBox controller hardware"));
                exec_check_silent(&vbox_pnpentity_vboxname_wmi, TEXT("Checking Win32_PnPDevice Name from WMI for VBOX names"));
                exec_check_silent(&vbox_bus_wmi, TEXT("Checking Win32_Bus from WMI"));
                exec_check_silent(&vbox_baseboard_wmi, TEXT("Checking Win32_BaseBoard from WMI"));
                exec_check_silent(&vbox_mac_wmi, TEXT("Checking MAC address from WMI"));
                exec_check_silent(&vbox_eventlogfile_wmi, TEXT("Checking NTEventLog from WMI"));
                exec_check_silent(&vbox_firmware_SMBIOS, TEXT("Checking SMBIOS firmware"));
            }

            if (ENABLE_VMWARE_CHECKS) {
                exec_check_silent(&vmware_dir, TEXT("Checking VMWare directory"));
                exec_check_silent(&vmware_firmware_SMBIOS, TEXT("Checking SMBIOS firmware"));
            }

            if (ENABLE_QEMU_CHECKS) {
                exec_check_silent(&qemu_firmware_SMBIOS, TEXT("Checking SMBIOS firmware"));
            }

            if (ENABLE_XEN_CHECKS) {
                exec_check_silent(&xen_check_mac, TEXT("Checking Mac Address start with 08:16:3E"));
            }

            if (ENABLE_KVM_CHECKS) {
                exec_check_silent(&kvm_dir, TEXT("Checking KVM virio directory"));
            }

            if (ENABLE_WINE_CHECKS) {
                exec_check_silent(&wine_exports, TEXT("Checking Wine via dll exports"));
            }

            if (ENABLE_PARALLELS_CHECKS) {
                exec_check_silent(&parallels_check_mac, TEXT("Checking Mac Address start with 00:1C:42"));
            }

            if (ENABLE_HYPERV_CHECKS) {
                exec_check_silent(&check_hyperv_driver_objects, TEXT("Checking for Hyper-V driver objects"));
            }

        }

        Sleep(2000);
    }
    return 0;
}
