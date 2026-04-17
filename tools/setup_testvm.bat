@echo off
REM GhostRing — Test VM Setup Script
REM Author: Baurzhan Atynov <bauratynov@gmail.com>
REM
REM Creates a VirtualBox VM with nested VT-x for testing GhostRing.
REM
REM Prerequisites:
REM   1. Disable Hyper-V:  bcdedit /set hypervisorlaunchtype off
REM      Then REBOOT.
REM   2. Install VirtualBox from tools\VirtualBox-7.1.8-Win.exe
REM   3. Run this script.

SET VBOXMANAGE="C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
SET VM_NAME=GhostRing-TestVM
SET VM_DIR=%USERPROFILE%\VirtualBox VMs\%VM_NAME%
SET ISO_PATH=%~dp0alpine-virt-3.21.3-x86_64.iso
SET DISK_SIZE=8192

echo ============================================
echo  GhostRing Test VM Setup
echo ============================================
echo.

REM Check VBoxManage exists
if not exist %VBOXMANAGE% (
    echo ERROR: VirtualBox not found at %VBOXMANAGE%
    echo Install VirtualBox first.
    pause
    exit /b 1
)

REM Check ISO exists
if not exist "%ISO_PATH%" (
    echo ERROR: Alpine ISO not found at %ISO_PATH%
    echo Download it first.
    pause
    exit /b 1
)

echo Creating VM: %VM_NAME%
%VBOXMANAGE% createvm --name "%VM_NAME%" --ostype "Linux_64" --register

echo Configuring: 4 CPUs, 4GB RAM, nested VT-x...
%VBOXMANAGE% modifyvm "%VM_NAME%" --cpus 4
%VBOXMANAGE% modifyvm "%VM_NAME%" --memory 4096
%VBOXMANAGE% modifyvm "%VM_NAME%" --vram 16
%VBOXMANAGE% modifyvm "%VM_NAME%" --nested-hw-virt on
%VBOXMANAGE% modifyvm "%VM_NAME%" --uart1 0x3F8 4
%VBOXMANAGE% modifyvm "%VM_NAME%" --uart-mode1 file "%VM_DIR%\serial.log"
%VBOXMANAGE% modifyvm "%VM_NAME%" --boot1 dvd --boot2 disk --boot3 none
%VBOXMANAGE% modifyvm "%VM_NAME%" --nat-pf1 "ssh,tcp,,2222,,22"

echo Creating 8GB disk...
%VBOXMANAGE% createmedium disk --filename "%VM_DIR%\disk.vdi" --size %DISK_SIZE% --format VDI

echo Attaching storage...
%VBOXMANAGE% storagectl "%VM_NAME%" --name "SATA" --add sata --controller IntelAhci
%VBOXMANAGE% storageattach "%VM_NAME%" --storagectl "SATA" --port 0 --device 0 --type hdd --medium "%VM_DIR%\disk.vdi"
%VBOXMANAGE% storageattach "%VM_NAME%" --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium "%ISO_PATH%"

echo.
echo ============================================
echo  VM Created: %VM_NAME%
echo ============================================
echo.
echo Next steps:
echo   1. Start VM:           VBoxManage startvm "%VM_NAME%"
echo   2. Install Alpine:     login as root, run "setup-alpine"
echo   3. Install packages:   apk add gcc make linux-headers musl-dev
echo   4. Share GhostRing:    mount -t vboxsf ghostring /mnt/ghostring
echo   5. Build module:       cd /mnt/ghostring/loader/linux ^&^& make
echo   6. Load:               insmod ghostring.ko
echo   7. Check serial log:   type "%VM_DIR%\serial.log"
echo.
echo Serial output goes to: %VM_DIR%\serial.log
echo SSH access: ssh -p 2222 root@localhost
echo.
pause
