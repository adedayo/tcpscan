curl -O https://raw.githubusercontent.com/adedayo/tcpscan/master/com.github.adedayo.libpcap.bpf-helper.sh
curl -O https://raw.githubusercontent.com/adedayo/tcpscan/master/com.github.adedayo.libpcap.bpf-helper.plist

sudo sh -c "mv com.github.adedayo.libpcap.bpf-helper.sh /Library/PrivilegedHelperTools/;\
mv com.github.adedayo.libpcap.bpf-helper.plist /Library/LaunchDaemons/;\
chown root:wheel /Library/PrivilegedHelperTools/com.github.adedayo.libpcap.bpf-helper.sh;\
chown root:wheel /Library/LaunchDaemons/com.github.adedayo.libpcap.bpf-helper.plist;\
chmod 755 /Library/PrivilegedHelperTools/com.github.adedayo.libpcap.bpf-helper.sh;\
launchctl load -w /Library/LaunchDaemons/com.github.adedayo.libpcap.bpf-helper.plist"

