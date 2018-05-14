# sdn-wan-hypervsior
Cross WAN Enclaves via SDN Hypervisor.

## Starting CORE 

- Install [CORE](https://github.com/coreemu/core), if using a virtual machine, ensure this repo is shared with the VM.
  - We assume that the repo can be accessed at `/home/$USER/hyper` on the machine running CORE
 
## Demo Network Overview

- A two institution network is in `demo.imn`, open this file in CORE.
- Institution 1:
  - n4 - the hypervisor node
  - Switches:
    - n1, n2: SDN capable switches that can be issued rules from guest controllers.
  - n3 - the SDN hypervisor switch
    - this switch allows guest controllers to connect to the hypervisor, but cannot be issued rules via guest controllers.
  - VPN Hosts:
    - One host for hypervisor traffic
    - Any number of hosts for enclave traffic. Here, we have two hosts that can be used for enclave traffic. If there are more that two enclaves, more hosts will need to be added.
    - Machines:
      - n5 - hypervisor traffic
      - n6 & n20 - enclave traffic
  - Guest Controller: n22 - an example guest controller for the first enclave
  - Hosts - hosts that are connected to switches and can be assigned to enclaves. 
    - n14, n15, n17, n18.
- Institution 2:
  - Mirrors the nodes in Institution 1. We do not have a guest controller in this institution. Rules will be issued from the guest controller in Institution 1.

## Configuring the Network

### Initialize SDN Capable Switches

Being by pressing the play button in the CORE network emulator to start the nodes.

The text "`nXX`:" indicates that the node should be double clicked so that commands can be entered.

#### Institution 2

`n11` Information
- dpid: 11141139
- up_port = 1

`n11`:
```bash
ifconfig ovsbr0 10.0.0.5/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.13:6633 
```

`n10` Information
- dpid: 11141135

`n10`:
```bash
ifconfig ovsbr0 10.0.0.4/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.13:6633
```

`n12` Information
- dpid: 11141141
- up_port = 1

`n12`:
```bash
ifconfig ovsbr0 10.0.0.6/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.13:6633
```

#### Institution 1

`n1` Information
- dpid: 11141120
- up_port = 1

`n1`:
```bash
ifconfig ovsbr0 10.0.0.1/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.10:6633 
```

`n3` Information
- dpid: 11141121

`n3`:
```bash
ifconfig ovsbr0 10.0.0.3/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.10:6633
```

`n2` Information
- dpid: 11141123
- up_port = 1

`n2`:
```bash
ifconfig ovsbr0 10.0.0.2/16 up
ovs-vsctl set-controller ovsbr0 tcp:10.0.0.10:6633
```

### Hypervisor Bootstrapping

We have to start the hypervisor in a single instituion at a time. The initial bootstrapping allows communication between local hypervisors over the VPN.
The inital configuration file also specifies machines that can be used as VPN hosts and information regarding switches in the local instituion.

We have to configure each SDN capable switch to point to a controller. This controller will be the hypervisor. All communication between
guest controllers and these switches is arbitrated by the hypervisor node


#### Institution 2 Hypervisor
`n13`:
```bash
/usr/local/bin/ryu-manager --observe-links /home/$HOME/Desktop/hyper/hypervisor.py
curl -H "Content-Type: application/json" -X POST -d '{"config_file_path": "/home/${HOME}/Desktop/hyper/config2"}' http://127.0.0.1:5678/start_system
```
#### Institution 1 Hypervisor

`n4`:
```bash
/usr/local/bin/ryu-manager --observe-links /home/yuen/Desktop/hyper/hypervisor.py
curl -H "Content-Type: application/json" -X POST -d '{"config_file_path": "/home/${HOME}/Desktop/hyper/config1"}' http://127.0.0.1:5678/start_system
```

### Creating Enclaves

Enclave creation is done in two steps. First the enclave must be created. The enclave creation end point allows the user to specify which 
institutions the enclave should span. Institutions are specified by the IP address of the hypervisor in that institution. The second step is to 
add physical ports to the enclave. Physical ports are denoted by the datapath id (the switch id) and the physical port on that switch. The 
IP address used for the endpoint can be a hypervisor in any institution. The institution of the hypervisor the request is issued to 
will be automatically added to the enclave. 

***Enclave Creation***

Enclave creation performs a number of actions:
- Reserves a VPN host for enclave traffic
- Creations enclaves across institutions via a two phase commit
  - Reserving an institution specific VLAN tag for enclave traffic

`n4`:

```bash
curl -H "Content-Type: application/json" -X POST -d '{"institutions":"10.0.0.13"}' http://127.0.0.1:5678/enclave/new
```

***Adding Physical ports***

`n4`:
```bash
curl -H "Content-Type: application/json" -X POST -d '{"enclave_id":1, "switch_port": 3, "datapath_id":11141120}' http://127.0.0.1:5678/enclave/add_port # n14
curl -H "Content-Type: application/json" -X POST -d '{"enclave_id":1, "switch_port": 3, "datapath_id":11141123}' http://127.0.0.1:5678/enclave/add_port # n15 
curl -H "Content-Type: application/json" -X POST -d '{"enclave_id":1, "switch_port": 3, "datapath_id":11141139}' http://10.0.0.13:5678/enclave/add_port # n16
```

### Starting Guest Controllers

Having created an enclave, we can now create a guest controller for the enclave and make the hypervsior aware of it. We'll use `n22` in the demo 
network for the guest controller.

***Start Guest Controller***
`n22`:
```bash
/usr/local/bin/ryu-manager --observe-links /home/yuen/Desktop/hyper/guest_controller.py
```

***Make Hypervisor Aware of Guest Controller*** 
`n4`:
```bash
curl -H "Content-Type: application/json" -X POST -d '{"enclave_id":1, "guest_controller_address": "10.0.0.24", "guest_controller_port": 6633, "connect_to_remote": true, "guest_controller_switch_port": 13}' http://127.0.0.1:5678/enclave/new_controller
```


### Resilience to Attack

Since we haven't added `n17` to enclave 1, we'll use it to demonstrate resilience to vlan and mac spoofing.

`n17`:

*** VLAN Spoofing ***
```bash
/sbin/modprobe 8021q
/sbin/vconfig add eth0 0
ifconfig eth0.0 10.0.0.30 up
ping 10.0.0.17 # Ping n15 in enclave 1
```

Assuming the attacker can use insider knowledge or other means of learning the IP address or MAC address of an enclave 1 node:

*** MAC Spoofing ***
`n17`
```bash
ifconfig eth0.0 hw ether 00:00:00:aa:00:18
ifconfig eth0.0 10.0.0.16 up
ping 10.0.0.17 # Ping n15 in enclave 1
```


