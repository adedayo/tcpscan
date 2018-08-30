#!/bin/sh

# Adapted from https://github.com/boundary/wireshark/blob/master/packaging/macosx/ChmodBPF/ChmodBPF
FORCE_CREATE_BPF_MAX=256
SYSCTL_MAX=$( sysctl -n debug.bpf_maxdevices )
	if [ "$FORCE_CREATE_BPF_MAX" -gt "$SYSCTL_MAX" ] ; then
		FORCE_CREATE_BPF_MAX=$SYSCTL_MAX
	fi
    
    syslog -s -l notice "ChmodBPF: Forcing creation and setting permissions for /dev/bpf*"

	CUR_DEV=0
	while [ "$CUR_DEV" -lt "$FORCE_CREATE_BPF_MAX" ] ; do
		# Try to do the minimum necessary to trigger the next device.
		read -n 0 < /dev/bpf$CUR_DEV > /dev/null 2>&1
		CUR_DEV=$(( $CUR_DEV + 1 ))
	done
	
chgrp admin /dev/bpf*
chmod g+rw /dev/bpf*
