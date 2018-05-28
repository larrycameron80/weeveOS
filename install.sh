#bin/bash
flash() {
    cd out
    echo "Flash device.."
    if [ -n "$1" ];then
	withDevice="-s $1"
	echo "using fastboot with: ${withDevice}"
    else
	withDevice=""
    fi
    
    fastboot ${withDevice} flash ptable prm_ptable.img
    fastboot ${withDevice} flash fastboot fip.bin
    fastboot ${withDevice} flash nvme nvme.img
    fastboot ${withDevice} flash boot boot-fat.uefi.img
    fastboot ${withDevice} flash system debian_system.img
    cd ..
    rm -r out
}

checkIfPackage(){
    SuccessMSG="Package is installed"
    requiredPackage="$1"
    isInstalled=$(dpkg-query -W --showformat="${SuccessMSG}" ${requiredPackage}  | grep "${SuccessMSG}")

    if [ "$SuccessMSG" != "$isInstalled" ]
    then
    	echo "${requiredPackage} is required. Trying to install it.."
	sudo apt-get --yes install ${requiredPackage}
    fi
}

extract(){
    echo "Extract images"
    #pv weeve.tar.gz | tar -xzf - -C . #for progress bar (pv needed)
    tar -xzf weeve.tar.gz
}

checkIfPackage "fastboot"
checkIfPackage "wget"



if [ -e "weeve.tar.gz" ]
then
    extract
    if [ -n "$1" ];then
        flash "$1"
    else 
	flash
    fi
else
    echo "Downloading images"
    wget https://dev.weeve.network/dl/weeve.tar.gz
    extract
    flash $1
fi 


