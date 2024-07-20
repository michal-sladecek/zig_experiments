VBOX_UUID=""
USERNAME=""
PROGRAM=$1


zig build -Doptimize=ReleaseFast -Dproject="$1" -Dtarget="x86_64-windows" -freference-trace &&
# make sure to rrun the VM and map the folder zig out to R: drive
vboxmanage guestcontrol $VBOX_UUID --username $USERNAME run -- "R:\\$PROGRAM.exe" 
