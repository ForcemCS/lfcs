##  模拟一

1）In the `/opt/findme/` directory you will find 10,000 files. You need to filter out specific files

1. Find all files that have the **executable** permission bit enabled for the **user that owns them**. Redirect the output of the find command to the `/opt/foundthem.txt` file.

   查找所有者具有可执行权限的文件

2. Find all files that have the **SETUID** permission enabled and delete them.

3. Find any file that is larger than **1KB** and copy it to the **/opt/** directory

```
1.find /opt/findme/ -perm /u=x -type f | sudo tee /opt/foundthem.txt
2.SETUID以文件的所有者运行，而不是程序用户运行，可以提升权限
sudo find /opt/findme/ -type f -perm /u=s -exec rm {} \;
3.sudo find /opt/findme/ -type f -size +1k -exec cp {} /opt/ \;
```

2）Perform the following two tasks:

1. Create a **bash script** that recursively copies the `/var/www/` directory into the `/opt/www-backup/` directory

   Save your script at `/opt/script.sh`. Remember, the script file you create also has to be **executable**.

2. Make sure that your script `/opt/script.sh` automatically runs every day at **4AM**. More specifically, create a cron job that runs that script every day at 4AM. Put this in the **system-wide cron table** (not root's local cron table) and make sure the script executes under the root user.

```
1.#!/bin/bash
  cp -a /var/www/. /opt/www-backup/
  
  chmod +x /opt/script.sh
2. sudo vi /etc/crontab
   0 4 * * *      root     /opt/script.sh
```

3）Enforce some **limits** on two users:

1. Set a limit on the user called **john** so that he can open no more than **30 processes**. This should be a **hard limit**.
2. For the user called **jane** make sure she can create **files not larger than 1024 kilobytes**. Make this a **soft limit**.

```
1.最多运行30个进程，是硬限制
/etc/security/limits.conf
john hard nproc 30
2.创建的单个文件暂时性不能超过1MB，是一个软限制
jane soft fsize 1024
```

4）Create a new user on this system called `mary`

- Set her password to `1234`.
- Leave the full name and other personal details empty.（全名和其他个人信息留空）
- Set her default shell to `/bin/dash`.
- Make sure she can **execute sudo commands** by adding her to the secondary group called `sudo`. 增加辅助组sudo
- At this point Mary's primary group is **mary**. And her secondary group is **sudo**. Change her primary group to `developers`. Without affecting her secondary group.

```
sudo useradd -m -s /bin/dash mary
echo "mary:1234" | sudo chpasswd
sudo usermod -aG sudo mary
sudo usermod -g developers mary 改变主要组

```

5）Modify the following **kernel runtime parameter**:

1. `vm.swappiness` set it to a value of `10`. This should be a persistent change, added to a file so that `vm.swappiness` is set to `10` every time the **system boots up**. However, after you create the proper file, **also set this runtime parameter to 10 for this session as well**. Otherwise said, the file will set the parameter to 10 the next time the system boots up, but we want to set it to 10 even for this current, active session, instead of waiting until the next boot until that takes effect.

```
sudo sysctl -w vm.swappiness=10
sudo nano /etc/sysctl.conf
vm.swappiness=10
sudo sysctl -p (生效)
cat /proc/sys/vm/swappiness（验证）
```

6）You have an **xfs filesystem** on **/dev/vdb1**. Also, there's an **ext4 filesystem** on **/dev/vdb2**. Finally, there's an empty partition **/dev/vdb3** that you'll need to format.

1. Edit the correct file in /etc/ so that **/dev/vdb1** is automatically mounted into the **/backups** directory every time the system boots up. **Default** mount options should be used.
2. **/dev/vdb2** is already mounted in **/mnt/**. But there is a problem. Sensitive data exists on this **ext4** filesystem and you want to make sure that it's not accidentally modified. To solve this problem, **remount /dev/vdb2 into the /mnt directory**, but this time, with the **read-only mount** option. It does not matter what the other mount options are. Just make sure this mount point is read-only so that users cannot change contents on this filesystem.
3. **Format /dev/vdb3** with the **xfs filesystem**. To make this easier to spot in the future among the other filesystems, set the filesystem label to **ExamFS** when you format it. Make sure that the label is exactly **ExamFS** and not **examfs** or anything that has different letters in UPPERCASE or lowercase

```
1./dev/vdb1    /backups    xfs    defaults    0    0
2.sudo mount -o remount,ro /dev/vdb2 /mnt 
3.sudo mkfs.xfs -L ExamFS /dev/vdb3
```

7）Use the Logical Volume Manager to perform the following tasks:

1. Add `/dev/vdc` and `/dev/vdd` as **Physical Volumes** to LVM.
2. Create a **Volume Group** on these two physical volumes. Call the volume `volume1`.
3. On the Volume Group called `volume1` create a new **Logical Volume**. Call this Logical Volume `website_files`. Set the size of the Logical Volume to `3GB`.

```
1.sudo pvcreate /dev/vdc /dev/vdd
2.sudo vgcreate volume1 /dev/vdc /dev/vdd
3.sudo lvcreate -n website_files -L 3G volume1
```

8）In your home directory you will find a subdirectory called **kode**. Git tools are pre-installed. Switch to the **kode** subdirectory and perform the following tasks:

1. **Initialize** this subdirectory as an **empty Git repository**.
2. Associate this local Git repository with the remote repository found at `https://github.com/kodekloudhub/git-for-beginners-course.git`. Add this as a remote repository and call it (alias it as) `origin`.
3. **Download** all the latest changes from the `master branch` from that remote repository into your local repository.

```
cd ~/kode
git init
git remote add origin https://github.com/kodekloudhub/git-for-beginners-course.git
git pull origin master
```

9）

```
sudo  docker run   -d       -p  8081:80  --restart=always --name webserver2 kodekloudwebserv
```

10）**NFS server and client tools** are installed on `caleston-lp10` system. Instruct the NFS server to share the **/home** directory in **read-only** mode with IP addresses in the **10.0.0.0/24** CIDR range.

```
# 打开 exports 文件  
sudo nano /etc/exports  
# 添加以下行以只读模式共享 /home 目录  
/home 10.0.0.0/24(ro,sync,no_subtree_check)  
# 导出共享  
sudo exportfs -a  
# 检查导出  
sudo exportfs -v  
# 重启 NFS 服务  
sudo systemctl restart nfs-server  
# （可选）设置 NFS 服务自动启动  
sudo systemctl enable nfs-server  


showmount -e localhost
```

11）查找正在接受 80 端口传入连接的应用程序。记下该应用程序的确切名称。稍后您会用到它。

在调查接受 80 端口传入连接的应用程序时，您可能会注意到有两个或多个 PID 与之相关。基本上，该应用程序分叉了多个进程来完成它的工作。找出哪个 PID 与主进程相关联。

注意到这两点后，创建以下文件： /opt/process.txt。

- 在第一行添加与 80 端口相关联的应用程序名称，全小写。
- 第二行添加与主进程相关的 PID 编号。

```
1.sudo netstat -tulpn | grep :80
2.pgrep -a nginx
```

12）Explore your network settings and perform the following tasks:

1. There is currently one network interface which does not have any IPv4 address associated with it. **Temporarily** assign it the following IPv4 address: **10.5.0.1/24**. This should not be a permanent change (no need to edit configuration files).
2. What is the **default route for this system**? Create a file, and add a single line where you save the IP address for the gateway used by this default route (i.e., requests are routed to what IP address?). Save the address in this file: `/opt/gateway.txt`.
3. For the final task, find out what is the IP address of the main **DNS resolver configured for this system**. Create the file `/opt/dns.txt` and add a single line to it with that IP address.

```
1.sudo ip addr add 10.5.0.1/24 dev eth1
2.ip route show default
3.cat /etc/resolv.conf
```

13）系统中添加了一个新磁盘。确定其设备名称。您可以识别该磁盘，因为它当前未分区，未加载到任何位置，大小为 4 GB。

- Create **two partitions** of equal size on this disk: **2GB** each.
- Create an **ext4** filesystem on the **first partition**.
- Create an **xfs** filesystem on the **second partition**.
- Create two directories: **/part1** and **/part2**.
- **Manually mount** the **ext4 filesystem** in the **/part1** directory. Manually mount the **xfs** filesystem in the **/part2** directory.
- Also, **configure the system to automatically mount** these the same way, every time the operating system boots up.

```
echo -e "g\nn\n\n\n+2G\nn\n\n\n+2G\nn\n\n\n\nw" | sudo fdisk /dev/vdb
sudo mkfs.ext4 /dev/vdb1
sudo mkfs.xfs /dev/vdb2
sudo mkdir /part1
sudo mkdir /part2
/dev/vdb1    /part1    ext4    defaults    0    2
/dev/vdb2    /part2    xfs    defaults    0    2
```

14）Configure the system to use `/swfile` as a swap file on **node01**.

1. First, create `/swfile`. Make the size of this file **exactly 1024 MB**.
2. Then take all the necessary steps to **temporarily mount this as swap**. (So that it's immediately used as swap for this current boot session).
3. But also make sure to **configure the system to also use this as swap every time it will boot** up in the future.

Credentials to access node01:
**Name**: `bob`
**Password**: `caleston123`

```
sudo fallocate -l 1024M /swfile
sudo chmod 600 /swfile
sudo mkswap /swfile
sudo swapon /swfile
/swfile none swap sw 0 0
```

15）On `node01`two processes are overusing our storage device. One is executing a lot of I/O operations per second (small data transfers, but a very large number of such transfers). Otherwise said, the process has a high **tps/IOPS**. The other process is **reading** very **large volumes of data**.

1. Identify the process with the **high tps**. What **partition** is it using? Create the file `/opt/devname.txt`and write the device name of that partition inside that file. For example, if it's using **/dev/vde5**, you would simply write **/dev/vde5** on a single line in that file. Note that there might be some abstractions behind this, and we're not interested in **device mapper** names, but rather, the **real device** the mapper is using.
2. Identify the process with the **high read transfer rate/second**. Create the file `/opt/highread.pid` and write the **PID number** of that process in that file. For example, if the PID is 3886 you just write 3886 in that file (only the number, on a single line).

Credentials to access node01:
**Name**: `bob`
**Password**: `caleston123`

```
To identify the process with high TPS and the partition it is using, follow the steps below:

Run the sudo dstat --top-io --top-bio command to get the process name with I/O activity.
Run the pgrep python3 command to get the PID of the process.
Run sudo lsof -p <PID> to list the open files by the process.
Run sudo lsof -p <PID> | awk '{print $9}' | while read file; do df $file; done to get the device details.
Find the actual partition used by running the pvs command and store the actual device name in /opt/devname.txt.
Run the command below to get the PID of the process with high kB_read/s:

   sudo pidstat -d 1


```

16）On `node01` list all filesystems to check out how much free space they have remaining. You'll find one which is almost full (should be around **98% full**). To confirm it is the correct filesystem, see where it is mounted, and you should find many directories on it in the form of numbers from 1 to 999. Find the directory which has the **largest file** and **delete that file (only that file, nothing else)**.

```
bob@node01:~$ sudo find /data -type f -exec du -h {} + | sort -rh | head -n 1
196M    /data/683/lf

Delete only the largest file:

sudo rm -rf /data/683/lf
```

17）On `caleston-lp10` change the configuration for the SSH daemon. **Disable** X11 forwarding **globally**. Then, make an exception for just one user called **bob**. For that user alone **enable** X11 forwarding.

Do not restart the SSH service after making the changes.

```
1) To disable X11 forwarding globally, find the line that contains X11Forwarding in /etc/ssh/sshd_config
. It may be commented out by default with a #. Change it to:

X11Forwarding no

2) To enable X11 Forwarding for User bob, add a conditional block at the end of the sshd_config file to enable X11 forwarding specifically for the user bob:

Match User bob
    X11Forwarding yes
```

## 模拟二

1）Configure the system to use the following **NTP pools**:

- `0.europe.pool.ntp.org`
- `1.europe.pool.ntp.org`

Next, change the **timezone** of this system to `Europe, Bucharest`.

```shell
1）vim /etc/systemd/timesyncd.conf
[Time]
NTP=0.europe.pool.ntp.org 1.europe.pool.ntp.org

systemctl restart systemd-timesyncd
2）timedatectl set-timezone Europe/Bucharest
```

2）Add a **cron job** for the user called **john**. Don't use the system-wide crontable, but rather add it to the personal crontable of the user called **john**.

Make sure that this cron job runs every **Wednesday at 4AM**. The command it should execute is `find /home/john/ -type d -empty -delete`.

Switch back to the bob user once the task is done.

```shell
1) Switch to user john

sudo su john

2)Edit the crontab using crontab -e command as shown below to run jobs every Wednesday at 4 AM:

0 4 * * 3 find /home/john/ -type d -empty -delete
```

3）There is a network interface on this system which has the IP address `10.5.5.2` associated with it. What is the name of this **network interface**? Create a file in `/opt/interface.txt` and add a single line to it containing the exact name of that interface.

```
ip -o -4 addr list | grep '10.5.5.2' | awk '{print $2}' |sudo  tee /opt/interface.txt
```

4）An administrator added a new user called `jane` to this system. But a few mistakes were made. Fix the following problems:

1. The administrator wanted to allow jane to run sudo commands. But instead of adding "jane" to the secondary/supplemental "sudo" group, the administrator changed the primary group to sudo. Fix this by doing the following: Set the **primary/login group** back to the group called `jane`. And add the user to the **secondary/supplemental group** called `sudo`. In essence the primary group for the user called "jane" should be "jane". And the secondary group should be "sudo".
2. Currently, the **home directory** path for the `jane` user is set correctly. But the directory itself is missing. Fix this by creating the `/home/jane/` directory. Make sure that the directory is owned by the `jane` user and `jane` group.
3. The **default shell** for the user called `jane` is set to **/bin/sh**. Change the default shell to `/bin/bash`.
4. Finally, set the password for `jane` to `1234`.

```shell
1) usermod -g jane jane

2) usermod -aG sudo jane

3) mkdir -p /home/jane  
   chown jane:jane /home/jane
   
4) usermod -s /bin/bash jane

5) echo 'jane:1234' | sudo chpasswd
```

5）Perform the following tasks:

1. Set up a port redirection rule that does the following: it **redirects** any **IPv4** packet from the `10.5.5.0/24` CIDR range incoming on port `81` to another machine with the IP address `192.168.5.2` on port `80`. To simplify this task, you are not required to specify input or output network interfaces.
2. Don't forget to add the proper **masquerading rule** so that packets redirected from `10.5.5.0/24` have a way of getting back to that sender, by our machine sitting in the middle and acting as an ad-hoc router between those two networks.
3. Make sure that after you add the rules you make them **persistent** (so that when the machine is rebooted these changes are not lost).

```
1) 来自一个私有网络的 HTTP 流量转发到另一个私有网络中的一台特定机器上，如果满足源地址（10.5.5.0/24），目标（端口是81，可能是网关）的话，则进行目标地址转换，将目标地址修改为192.168.5.2:80
sudo iptables -t nat -A PREROUTING -p tcp -s 10.5.5.0/24 --dport 81 -j DNAT --to-destination 192.168.5.2:80

2)  POSTROUTING发送到网络之前进行处理，当 192.168.X.X 收到请求并回复时，会将回复数据包的源地址修改为网关的 IP 地址，并将其发送回 10.X.X.0/24 网段的设备。
iptables -t nat -A POSTROUTING -s 10.5.5.0/24 -j MASQUERADE

3) To make iptables rules persistent:

sudo apt install iptables-persistent
```

```
1）端口5000应关闭
iptables -A INPUT -i eth0 -p tcp --dport 5000 -j DROP
2）将端口6000上的所有流量重定向到本地端口6001
iptables -A PREROUTING -i eth0 -t nat -p tcp --dport 6000 -j REDIRECT --to-port 6001
3）端口6002只能从 IP 192.168.10.80 （服务器data-001 ）访问
iptables -A INPUT -i eth0 -p tcp --dport 6002 -s 192.168.10.80 -j ACCEPT
4）阻止所有到 IP 192.168.10.70的传出流量（服务器app-srv1 ）
iptables -A OUTPUT -d 192.168.10.70 -p tcp -j DROP
```

6）In `/home/bob/certs/` directory you will find 4 files. That's because we generated two self-signed TLS certificates for you. **Delete the 2 files containing the private keys**. But **preserve the certificate files**.

At this point you're left with 2 files containing 2 separate certificates. They both use the RSA algorithm. But one is using 2048 bits for its cryptography purposes, while the other is using 4096. **Delete the certificate that is using 2048 bits**.

```
openssl  x509  -in  xx  -noout  -text
```

7）There is a file at `/opt/aclfile`. Currently no one has permissions to read, write, or execute this file, not even root. But instead of working with regular permissions, use **ACL** for this task. Add the following to the access control list:

The user called `janet` should be able to **read and write** to `/opt/aclfile`. Just read and write, no execute permission for this **ACL entry**.

```
sudo setfacl -m u:janet:rw /opt/aclfile
```

```
1）修改 file.txt 的 ACE，增加组 admin 的执行权限
setfacl -m g:admin:x file.txt
2）rm -rf /home/delete.me 会收到一条报错，即使是root也没有权限
   + 列出lsattr /home/delete.me 权限（lsattr /home/delete.me ）
   + 删除 delete.me 中的 “i ”属性（chattr -i /home/delete.me ）
   
```

8）Add **two security limits** to the configuration of this system:

1. The user called `janet` should have a `hard`` limit so that she can't open more than`100`processes`.
2. The group called `mail` should have a `soft` limit so users in the group not be able to create files larger than `8192 kilobytes`.

```shell
/etc/security/limits.conf 

janet hard nproc 100
@mail soft fsize 8192
```

9）In your home directory you will find a subdirectory called `project`. Navigate to it and then do the following:

1. Add `file1` to the staging area to prepare it for a future commit.
2. Commit this file with the exact following message: `Created first required file`.
3. Now upload your changes to the remote repository already associated with your local repository. Everything is already set up for you. Use the remote repository aliased as origin and upload the `master` branch and password to push the code is `C0ntr0lplan3Pa$$wd`.

10）Perform the following tasks related to **SELinux** on `node01`:

1. First, check if SELinux is running in **enforcing**, **permissive**, or **disabled** mode. Create the file `/opt/selinuxmode.txt`. And write your answer to that file. Just one line where you write a single word: enforcing, permissive, or disabled, according to the status you found.
2. There is a file that has the **wrong SELinux type label**. Please correct that and restore the **default SELinux label** for the file at `/usr/bin/less`.

```
restorecon  -v /usr/bin/less
```

11）**Nginx** is installed but it's **not running** on `caleston-lp10`. Make the necessary changes so that:

1. Nginx is started immediately.
2. And also, Nginx will start up automatically every time the system boots up.

After starting Nginx, it has spawned at least **3** processes. We are not interested in the **master** process, only the **worker** processes. Under what **username** are these **worker** processes running? Create a new file at `/opt/nginxuser.txt` and add a single line to it with that username, other than **bob**.

```
ps   -ef   |grep  nginx 
```

12）A basic **LVM** structure exists on the `node01`. Make some changes to it:

The volume group called `volume1` currently only includes `/dev/vdb`. Add `/dev/vdc` to `volume1`.
We have a logical volume called lv1`. Resize this logical volume to`2GB`.

```shell
1) Add /dev/vdc to volume1:
sudo vgextend volume1 /dev/vdc

2) Resize the Logical Volume lv1 to 2GB:
sudo lvresize --size 2G /dev/volume1/lv1
```

```
fdisk /dev/xvdb

pvcreate /dev/xvdb1 /dev/xvdb2

vgcreate vg01 /dev/xvdb1 /dev/xvdb2

lvcreate  -n lv01   -L 2G vg01

mkfs.ext3  -L lv01  /dev/vg01/lv01

/dev/vg01/lv01  /mnt  ext3   defaults  0 0

mount /mnt

```

13）Create a **virtual machine** with the following parameters on `caleston-lp10`:

1. For the **operating system information parameter** use the `ubuntu22.04`.
2. Name the virtual machine `mockexam2`.
3. Assign `1024 MB` of RAM to this machine.
4. Assign it `one virtual CPU`.
5. Import the disk image `/var/lib/libvirt/images/ubuntu.img` to this virtual machine.
6. At the end of your command, you can add the parameter `--noautoconsole` to avoid waiting for this virtual machine to boot up, and not get stuck in the virtual console after it initializes.

After you create this virtual machine, run a separate command to make `mockexam2` automatically start up every time the system boots up.

```
virt-install \
--name mockexam2 \
--ram 1024 \
--vcpus=1 \
--os-variant=ubuntu22.04 \
--import \
--disk path=/var/lib/libvirt/images/ubuntu.img \
--noautoconsole

virsh autostart mockexam2
```

14）Create a network bridge between these network interfaces: `[ "eth1", and "eth2"]` on `node01`. Call the bridge `bridge1`. Turn **DHCP off** for IPv4 **for both interfaces**. However, for the **bridge** itself, turn **DHCP** on for **IPv4**.

```yaml
/etc/netplan/99-bridge.yaml

network:
  version: 2
  renderer: networkd
  ethernets:
    eth1:
      dhcp4: no
    eth2:
      dhcp4: no
  bridges:
    bridge1:
      dhcp4: yes
      interfaces:
        - eth1
        - eth2
```

15）Perform the following tasks on `node01`:

1. Remove the Docker image called `nginx`.
2. Start a container based on the `httpd` image. **Name** it `apache_container`. Instruct Docker to redirect connections coming to port 80 on the host to port 80 of this container. Also instruct Docker to `restart` this container `only on failure`, with a **maximum number of retries** set to `3` (you will have to look through the correct manual to find the parameter you need).

```
docker run --detach --publish 80:80 --name=apache_container --restart=on-failure:3 httpd
```

16）The `node01` was configured to use `LDAP` entries from a certain server. However, some configuration options are wrong. Edit the correct configuration files and fix the following mistakes:

1. Our name service local daemon is configured to look for an **LDAP server** at the **wrong IP address** (currently **10.9.9.8**). Fix this and configure the correct IP which is: **`192.168.121.167`**. Make sure your changes become active after you edit the configuration file.
2. Our system is currently configured to get **group data** and **password data** from the LDAP server but not user data. Configure it to get **user data** as well.

```
Solution
Edit /etc/nslcd.conf to change the ldap server:
# The user and group nslcd should run as.
uid nslcd
gid nslcd

# The location at which the LDAP server(s) should be reachable.
uri ldap://192.168.121.167/ #updated

# The search base that will be used for all queries.
base dc=example,dc=org

# The LDAP protocol version to use.
#ldap_version 3

# The DN to bind with for normal lookups.
#binddn cn=annonymous,dc=example,dc=net
#bindpw secret

Edit /etc/nsswitch.conf to get user data:
# /etc/nsswitch.conf
#
# Example configuration of GNU Name Service Switch functionality.
# If you have the `glibc-doc-reference' and `info' packages installed, try:
# `info libc "Name Service Switch"' for information about this file.

passwd:         files systemd ldap #updated
group:          files systemd ldap
shadow:         files ldap
gshadow:        files

Restart the nslcd service:
sudo systemctl restart nslcd
```

## 模拟三

1）Nginx is installed and a configuration file for running Nginx as a reverse proxy is already available. Perform the following tasks:

1. Disable the default Nginx website configuration.
2. Find the correct file where the reverse proxy configuration for Nginx is defined. Edit this file and make it redirect requests to "google.com".
3. Make Nginx use this configuration file so that it starts working as a reverse proxy.

```
sudo rm /etc/nginx/sites-enabled/default

cat  /etc/nginx/sites-available/proxy.conf
server {
    listen 80;
    location / {
        proxy_pass http://google.com;
        include proxy_params;
    }
}

sudo ln -s /etc/nginx/sites-available/proxy.conf /etc/nginx/sites-enabled/proxy.conf
sudo systemctl reload nginx.service
```

2）Add a cron job to the system-wide cron table. This cron job should run as a user called **`Mary`**, on the **`15th day`** of **`every month`**, at **`4 AM`***. The command that the cron job should execute is: **`find /home/mary/ -type d -empty -delete`**.

```
Open the root crontab file:
sudo crontab -e

Add the cron job entry at the end of the file:
0 4 15 * * su - mary -c 'find /home/mary/ -type d -empty -delete'
- 表示切换到mary的环境下执行相关的任务
```

3）Make some changes to the network configuration settings of the interface called **`enp0s10`** using **`netplan`**.

1. First, make a persistent change to the correct configuration file. There are two routes defined for our network interface. Remove the route that sends network packets to **`192.168.1.0/24`** through the server at **`10.198.0.2`**. Make sure that your changes are applied.
2. Next, add a temporary IP address to our interface. Assign it the following IP: **`10.5.0.9/24`**. No configuration files should be edited for this second task.

```
lolFor first task in this question, we need to edit netplan configuration file.
sudo vim /etc/netplan/extrainterface.yaml ，Remove the route configured to send network packets.
network:
  version: 2
  ethernets:
    enp0s10:
      dhcp4: false
      dhcp6: false
      addresses:
        - 10.198.0.5/24
      routes:
        - to: 192.168.0.0/24
          via: 10.198.0.1

Apply the configuration
sudo netplan apply
Check whether the configuration is applied by below command.
#ip route

For second task in this question add a temporary IP address by the below command
#sudo ip addr add 10.5.0.9/24 dev enp0s10
```

4）Change the following kernel parameters:

1. Set **`vm.swappiness to 30`**. Make this a non-persistent change that will be lost at the next reboot.
2. Set **`vm.dirty_ratio to 15`**. Make this a persistent change so that it survives across reboots.

```
sudo sysctl vm.swappiness=30

sudo vim /etc/sysctl.conf
vm.dirty_ratio = 15
```

5）Perform the following tasks:

1. Add a group called **`developers`**.
2. Add a user called **`jane`**. When creating the account, go with the system defaults. That is, the user's home directory should be set to **`/home/jane`**, and the default shell should be **`/bin/bash`**. You can pick any password you want for this user.
3. After the user **`jane`** was created, perform the following changes. Set her primary/login group to **`developers`**. And set her secondary groups to **`jane`** and **`sudo`**.

```
sudo groupadd developers
sudo adduser jane
sudo usermod -g developers jane
sudo usermod -aG jane,sudo jane
```

6）Edit the configuration of the SSH daemon. Disable password logins globally (for all users). But make an exception for a single user. The user called "john" should be allowed to log in with a password.

Don't apply changes now.

Note: There's also a setting related to "Keyboard Interactive Authentication" that can in some cases affect password authentication settings. But you can ignore that setting for the purposes of this task.

```
sudo vim /etc/ssh/sshd_config
PasswordAuthentication no
Match User john
    PasswordAuthentication yes
```

7）

```
sudo find /usr -type f -size +1G -delete
```

8）We've provided two storage devices that can be accessed at **`/dev/vdb`** and **`/dev/vdc`**. Add these as physical volumes to LVM, then set up a volume group that includes both devices. Call this volume group **`VG1`** (uppercase letters). On this volume group, add a logical volume of exactly **`6 GB`**. Call this logical volume **`LV1`** (uppercase letters).

```
sudo pvcreate /dev/vdb /dev/vdc

sudo vgcreate VG1 /dev/vdb /dev/vdc

sudo lvcreate -L 6G -n LV1 VG1
```

9）Set up iptables rules that will redirect all incoming network connections from "10.11.12.0/24" to "10.9.9.1". Remember the matching masquerade rule (so traffic can be returned to 10.11.12.0/24).

```
sudo iptables -t nat -A PREROUTING -s 10.11.12.0/24 -p tcp -j DNAT --to-destination 10.9.9.1

sudo iptables -t nat -A POSTROUTING -s 10.11.12.0/24 -j MASQUERADE
```

10）Format **`/dev/vdd`** with the `ext4` filesystem. Then set up the system to automatically `mount` **`/dev/vdd`** into the **`/home/bob/backups`** directory every time it boots up.

```
sudo mkfs.ext4 /dev/vdd

sudo vim /etc/fstab
/dev/vdd /home/bob/backups ext4 defaults 0 2

sudo mount -a  
```

11）A process is overusing CPU resources. Find the most CPU-intensive process and close it.

```
ps  aux   --sort=-%cpu |head  -n 5
```

12）We have a Network Block Device (NBD) server running at the IP address **`127.0.0.1`**. Perform the following tasks:

1. A network block device is already attached to this system and mounted to a certain directory. Unmount the network block device from that directory. Then disconnect the network block device from the system.
2. List the exports available on the NBD server at **`127.0.0.1`**. Attach the second export to this system, and then mount it to the **`/mnt`** directory.

Use `lsblk` command to get details of network block devices.

```sh
bob@node01:~$ lsblk
NAME   MAJ:MIN RM SIZE RO TYPE MOUNTPOINTS
nbd0    43:0    0   2G  0 disk /share
```

Unmount the network block device from that directory.

```sh
sudo umount /share
```

Disconnect the network block device from the system.

```sh
sudo nbd-client -d /dev/nbd0
```

Run the below command to find the second export name:

```sh
sudo nbd-client -l 127.0.0.1
```

Attach the second export to this system

```sh
sudo nbd-client 127.0.0.1 -N disk2
```

Mount `disk2` to the `/mnt` directory

```sh
sudo mount /dev/nbd0 /mnt
```

## 模式四

1）Nginx is installed and a configuration file is available to make it work as a load balancer. However, some steps are still required:

1. Edit the provided configuration file and add another server for load balancing.
2. The server's IP is **`10.9.0.3`**. Assign it a weight equal to **`3`** so that requests are sent to this server more often.
3. Take the rest of the steps necessary to make this new configuration active for Nginx.

```
sudo ln -s /etc/nginx/sites-available/loadbalancer.conf /etc/nginx/sites-enabled/loadbalancer.conf
sudo systemctl reload nginx
```

2）dd a cron job to the crontable of the user called **`john`** (not the system-wide crontable).

1. This cron job should be executed every **`Monday and Saturday at 3 AM (03:00)`**.
2. The command executed by this cron job should be:
   **`tar acf /home/john/www-snapshot.tgz /var/www`**

Important note: The crontable entry should be specified on a single line (not one line for Monday and a separate one for Friday).

```
sudo crontab -e -u john

Add the following line:

0 3 * * 1,6 tar acf /home/john/www-snapshot.tgz /var/www
```

3）We've created a configuration file that defines a network bond between two interfaces. But we haven't activated it yet.

1. Change that configuration file to make **`eth3`** the primary interface of this network bond.
2. Activate the new network settings defined in that file, so that the network bond gets created accordingly.

```
network:
  version: 2
  renderer: networkd
  ethernets:
    eth2:
      dhcp4: no
    eth3:
      dhcp4: no
  bonds:
    bond0:
      dhcp4: yes
      interfaces:
        - eth2
        - eth3
      parameters:
        mode: active-backup
        primary: eth3
```

4）The systemd-timesyncd package is already installed. However, automatically setting up the correct time by using NTP servers is currently disabled.

1. **`Enable`** NTP time synchronization on this machine.
2. Then set the timezone to **`Asia, Singapore`**.
3. Finally, what is the name of the fallback NTP pool currently configured for this system? Create the file **`/opt/pool.txt`** and save the name of that pool there, on a single line.

```
Enable NTP time synchronization:
sudo timedatectl set-ntp true

Set the timezone to Asia, Singapore:
sudo timedatectl set-timezone Asia/Singapore

Find the fallback NTP pool and save it to /opt/pool.txt:
sudo timedatectl show-timesync | grep FallbackNTP | sudo tee /opt/pool.txt > /dev/null
```

5）The Logical Volume Manager was used to create the following structure:

- A volume group called VG1.
- A logical volume called LV1.
- On this logical volume we have an ext4 filesystem of approximately 2GB.

1. Expand the logical volume called LV1 to use 100% of the free space available on the VG1 volume group.

```
sudo lvresize --extents 100%VG VG1/LV1
```

The **`/var/www/`** directory and all of its content is currently labeled like this under SELinux:
**`unconfined_u:object_r:var_t:s0`**

1. Change the label on the **`/var/www/`** directory itself, its subdirectories, and all the files it contains. More specifically, change the SELinux type on these objects to **`httpd_sys_content_t`**. At the end of this task, everything in **`/var/www/`** (and the directory itself) should end up with the following label:

```
sudo chcon -R -t httpd_sys_content_t /var/www
```

6）In the **`/opt/archive/`** directory there is a single file with the permission to be executed by its user. Find the user's executable file and delete it.

```
find /opt/archive/ -type f -perm /u=x
```

7）Find the filesystem that is almost full (100% of available space is used, or very close to 100%). Free up some space by deleting the largest file from that filesystem.

```
df -h

sudo find /mnt -type f -exec ls -s {} + | sort -n -r | head -1 | awk '{print $2}' | xargs sudo 
```



```
PasswordAuthentication no

Match User john
    PasswordAuthentication yes
    ChallengeResponseAuthentication yes
```

```
lvextend -L +5G /dev/volgroup00/mylogicalvol
```

```
sudo iptables-save > /etc/iptables/rules.v4
```

```
virt-install \
--name mockexam2 \
--ram 1024 \
--vcpus=1 \
--os-variant=ubuntu22.04 \
--import \
--disk path=/var/lib/libvirt/images/ubuntu.img \
--noautoconsole

virsh autostart mockexam2
```

```
# 打开 exports 文件  
sudo nano /etc/exports  
# 添加以下行以只读模式共享 /home 目录  
/home 10.0.0.0/24(ro,sync,no_subtree_check)  
# 导出共享  
sudo exportfs -a  
# 检查导出  
sudo exportfs -v  
# 重启 NFS 服务  
sudo systemctl restart nfs-server  
# （可选）设置 NFS 服务自动启动  
sudo systemctl enable nfs-server  


showmount -e localhost
```

