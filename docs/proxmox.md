# Proxmox Virtual Environment

## Prerequisites

### Authentication

For authentication the following data is needed:

- `user_id` is expected to be in the form `USER@REALM!TOKENID`
- `token` is just the UUID you get when initially creating the token

See also:
* https://pve.proxmox.com/wiki/User_Management#pveum_tokens
* https://pve.proxmox.com/wiki/Proxmox_VE_API#API_Tokens

### Cloud-Init enabled VM Templates

Although it is possible to upload Cloud-Init images in Proxmox VE and create VM disks directly from
these imgages via CLI tools on the nodes directly, there is no API endpoint yet to provide this
functionality externally. That's why the `proxmox` provider assumes there are VM templates in place
to clone new machines from.

Proxmox recommends to use either ready-to-use Cloud-Init images provided by many Linux distributions
(mostly designed for OpenStack) or to prepare the images yourself as you have full controll over
what's in these images.

Example for creating a VM template:
```bash
cd /var/lib/vz/template/iso
wget http://cdimage.debian.org/cdimage/openstack/current-10/debian-10-openstack-amd64.qcow2
INSTANCE_ID=9000
qm create $INSTANCE_ID -name debian-cloudinit
qm importdisk $INSTANCE_ID debian-10-openstack-amd64.qcow2 local
qm set $INSTANCE_ID -scsihw virtio-scsi-pci
qm set $INSTANCE_ID -virtio0 local:$INSTANCE_ID/vm-$INSTANCE_ID-disk-0.raw
qm set $INSTANCE_ID -serial0 socket
qm set $INSTANCE_ID -vga serial0
qm set $INSTANCE_ID -boot c
qm set $INSTANCE_ID -bootdisk virtio0
qm set $INSTANCE_ID -net0 virtio,bridge=vmbr0
qm set $INSTANCE_ID -agent 1
qm set $INSTANCE_ID -hotplug disk,network,usb
qm set $INSTANCE_ID -ide2 local:cloudinit
qm resize $INSTANCE_ID virtio0 2G
qm template $INSTANCE_ID
```


