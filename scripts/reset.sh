VBoxManage controlvm "knode1" poweroff
VBoxManage controlvm "knode2" poweroff
VBoxManage controlvm "knode3" poweroff
VBoxManage controlvm "knode4" poweroff
VBoxManage controlvm "snode1" poweroff
VBoxManage controlvm "snode2" poweroff
VBoxManage snapshot "knode1" restore "cve"
VBoxManage snapshot "knode2" restore "cve"
VBoxManage snapshot "knode3" restore "cve"
VBoxManage snapshot "knode4" restore "cve"
VBoxManage snapshot "snode1" restore "cve"
VBoxManage snapshot "snode2" restore "cve"
VBoxManage startvm "knode1" --type headless
VBoxManage startvm "knode2" --type headless
VBoxManage startvm "knode3" --type headless
VBoxManage startvm "knode4" --type headless
VBoxManage startvm "snode1" --type headless
VBoxManage startvm "snode2" --type headless
