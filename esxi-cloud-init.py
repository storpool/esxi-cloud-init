#!/bin/python
import crypt
import logging
import re
import subprocess
import json
import glob
import time
import select
import os
import fcntl
import urllib.request

CLASSLESS_ROUTE_PATTERN = re.compile(r"169\.254\.169\.254 ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]),0")
DHCP_IDENTIFIER_PATTERN = re.compile(r"dhcp-server-identifier ([0-9]*\.[0-9]*\.[0-9]*\.[0-9]);")


def run_cmd(args, ignore_failure=False, retry=1):
    logging.debug(f"Executing command: {' '.join(args)}")

    while retry > 0:
        retry -= 1
        try:
            output = subprocess.check_output(args)
            logging.debug(f"Output: {output.decode()}")
            return output
        except subprocess.CalledProcessError:
            if retry:
                time.sleep(1)
                continue
            if not ignore_failure:
                raise


def find_cdrom_dev():
    mpath_b = run_cmd(['esxcfg-mpath', '-b'])
    for line in mpath_b.decode().split('\n'):
        m = re.match(r'^(\S*).*\sCD-ROM\s.*', line)
        if m:
            return m.group(1)


def mount_cdrom(cdrom_dev):
    run_cmd(['vsish', '-e', 'set', '/vmkModules/iso9660/mount', cdrom_dev])


def umount_cdrom(cdrom_dev):
    run_cmd(['vsish', '-e', 'set', '/vmkModules/iso9660/umount', cdrom_dev])


def load_network_data():
    # Should be openstack/latest/network_data.json
    with open('/vmfs/volumes/config-2/openstack/latest/network_data.json', 'r') as fd:
        return json.loads(fd.read())


def load_meta_data():
    if os.path.exists('/vmfs/volumes/config-2/openstack/latest/meta_data.json'):
        fd = open('/vmfs/volumes/config-2/openstack/latest/meta_data.json', 'r')
        raw_content = fd.read()
    else:
        try:
            fd = urllib.request.urlopen('http://169.254.169.254/openstack/latest/meta_data.json')
            raw_content = fd.read().decode()
        except urllib.error.URLError:
            return {}
    data = json.loads(raw_content)
    return data


def load_user_data():
    # Should be openstack/latest/user-data
    content = None
    try:
        content = open('/vmfs/volumes/config-2/openstack/latest/user_data', 'r').read()
    except FileNotFoundError:
        pass
    try:
        if not content:
            content = urllib.request.urlopen('http://169.254.169.254/openstack/latest/user_data').read().decode()
    except urllib.error.URLError:
        pass

    if not content:
        return {}

    user_data = {}
    for line in content.split("\n"):
        if line.startswith('#'):
            continue
        if not re.match(r'.*:.+', line):
            continue

        k, v = line.split(': ', 1)
        v = v.rstrip()
        if v.startswith("'") and v.endswith("'"):
            v = v[1:-1]
        user_data[k] = v.rstrip()
    return user_data


def set_hostname(fqdn):
    if fqdn:
        run_cmd(['esxcli', 'system', 'hostname', 'set', '--fqdn=%s' % fqdn], retry=3)


def set_network(network_data):
    run_cmd(['esxcfg-vswitch', '-a', 'vSwitch0'], ignore_failure=True)
    run_cmd(['esxcfg-vswitch', '-A', 'Management Network', 'vSwitch0'], ignore_failure=True)
    run_cmd(['esxcfg-vswitch', '-L', 'vmnic0', '-p', 'Management Network', 'vSwitch0'], ignore_failure=True)

    # ESX's switch has no learning mode and enforce the MAC/port by default
    # With this line, we ensure a nested ESXi can contact the outside world
    run_cmd(['esxcli', 'network', 'vswitch', 'standard', 'policy', 'security', 'set', '--allow-promiscuous=1',
             '--allow-forged-transmits=1', '--allow-mac-change=1', '--vswitch-name=vSwitch0'])
    link_by_id = {i['id']: i for i in network_data['links']}
    open('/etc/resolv.conf', 'w').close()
    # Assuming one network per interface and interfaces are in the good order
    # and only set the first interface
    ifdef = network_data['networks'][0]
    link = link_by_id[ifdef['link']]
    if ifdef['type'] == 'ipv4':
        run_cmd(['esxcfg-vmknic', '-a', '-i', ifdef['ip_address'], '-n', ifdef['netmask'], '-m',
                 str(link.get('mtu', '1500')), '-M', link['ethernet_mac_address'], '-p', 'Management Network'])
    else:
        run_cmd(['esxcfg-vmknic', '-a', '-i', 'DHCP', '-m', str(link.get('mtu', '1500')), '-M',
                 link['ethernet_mac_address'], '-p', 'Management Network'], ignore_failure=True)
        poll_for_dhcp_lease()
        run_cmd(['esxcli', 'network', 'ip', 'route', 'ipv4', 'add',
                 '-g', get_metadata_service_address(), '-n', '169.254.169.254/32'], ignore_failure=True)

    r = {}
    for r in ifdef.get('routes', []):
        if r['network'] == '0.0.0.0':
            network = 'default'
        else:
            network = r['network']
    if 'gateway' in r:
        run_cmd(['esxcli', 'network', 'ip', 'route', 'ipv4', 'add', '-g', r['gateway'], '-n', network])

    for s in network_data.get('services', []):
        if s['type'] == 'dns':
            run_cmd(['esxcli', 'network', 'ip', 'dns', 'server', 'add', '--server', s['address']])


def set_ssh_keys(public_keys):
    if not public_keys:
        return
    # A bit hackish because PyYAML because ESXi's Python does not provide PyYAML
    add_keys = public_keys.values()
    current_keys = []

    with open('/etc/ssh/keys-root/authorized_keys', 'r') as fd:
        for line in fd.readlines():
            m = re.match(r'[^#].*(ssh-\S+\s\S+).*', line)
            if m:
                current_keys.append = fd.group(1)

    with open('/etc/ssh/keys-root/authorized_keys', 'a+') as fd:
        for key in set(add_keys):
            if key not in current_keys:
                fd.write(key + '\n')


def allow_nested_vm():
    with open('/etc/vmware/config', 'r') as fd:
        for line in fd.readlines():
            m = re.match(r'^vmx.allowNested', line)
            if m:
                return
    with open('/etc/vmware/config', 'a+') as fd:
        fd.write('\nvmx.allowNested = "TRUE"\n')


def set_root_pw(password):
    hashed_pw = crypt.crypt(password, crypt.mksalt(crypt.METHOD_SHA512))
    current = open('/etc/shadow', 'r').readlines()
    with open('/etc/shadow', 'w') as fd:
        for line in current:
            s = line.split(':')
            if s[0] == 'root':
                s[1] = hashed_pw
            fd.write(':'.join(s))


def turn_off_firewall():
    run_cmd(['esxcli', 'network', 'firewall', 'set', '--enabled', 'false'])


def restart_service(service_name):
    run_cmd(['/etc/init.d/%s' % service_name, 'restart'])


def enable_ssh():
    run_cmd(['vim-cmd', 'hostsvc/enable_ssh'])
    run_cmd(['vim-cmd', 'hostsvc/start_ssh'])


def localhost_over_ipv4():
    run_cmd(['sed', '-i', "s,^::1,#::1,", '/etc/hosts'])


def turn_tally2_off():
    run_cmd(['sed', '-i', "s,^,# disabled by esxi-cloud-init.py,", '/etc/pam.d/system-auth-tally'])


def create_local_datastore():
    root_disk = glob.glob('/vmfs/devices/disks/t10*:1')[0].split(':')[0]  # TODO: probably kvm specific

    proc = subprocess.Popen(['partedUtil', 'fixGpt', root_disk], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            stdin=subprocess.PIPE)
    fd = proc.stdout.fileno()
    fl = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    while True:
        time.sleep(.5)
        if len(select.select([proc.stdout, proc.stderr], [], [], 0)[0]) == 0:
            continue
        out = ''
        try:
            out = proc.stdout.read()
        except TypeError as e:
            continue
        if 'Are you sure you want to continue' in out.decode():
            proc.stdin.write('Y\n'.encode())
            proc.stdin.flush()
        elif 'The backup GPT table is not' in out.decode():
            proc.stdin.write('Fix\n'.encode())
            proc.stdin.flush()

        if proc.poll() is not None:
            break

    getptbl_output = subprocess.check_output(['partedUtil', 'getptbl', root_disk]).decode().split('\n')
    geometry = getptbl_output[1]
    last_partition = getptbl_output[-2]
    last_sector_in_use = int(last_partition.split()[2])
    quantity_of_cylinders = int(geometry.split()[3])
    new_partition_partnum = max([int(i.split()[0]) for i in getptbl_output[2:-1]]) + 1
    new_partition_first_sector = last_sector_in_use + 4096
    new_partition_last_sector = quantity_of_cylinders - 4096

    if new_partition_last_sector - new_partition_first_sector > 4096 * 1024:
        logging.info(subprocess.check_output(["partedUtil", "add", root_disk, "gpt",
                                       "%s %s %s AA31E02A400F11DB9590000C2911D1B8 0" % (
                                       new_partition_partnum, new_partition_first_sector, new_partition_last_sector)]))
        logging.info(subprocess.check_output(
            ["vmkfstools", "-C", "vmfs6", "-S", "local", "%s:%s" % (root_disk, new_partition_partnum)]))


def get_nic_mac_address(vmnic):
    vnics = get_vnics_list()
    vnics_filtered = [vnic for vnic in vnics if vnic["name"] == vmnic]

    if len(vnics_filtered):
        return vnics_filtered[0]["mac_address"]
    else:
        raise KeyError(f"No vnic called {vmnic} found")


def get_vnics_list():
    vnics_list = list()

    raw = run_cmd(["esxcli", "network", "nic", "list"]).decode()
    # Name    PCI Device    Driver  Admin Status  Link Status  Speed  Duplex  MAC Address         MTU  Description
    # ------  ------------  ------  ------------  -----------  -----  ------  -----------------  ----  -----------------------------------------------------
    # vmnic0  0000:00:03.0  e1000   Up            Up            1000  Full    fa:16:3e:25:bd:9f  1500  Intel Corporation 82540EM Gigabit Ethernet Controller
    # vmnic1  0000:00:04.0  e1000   Up            Up            1000  Full    fa:16:3e:a3:d8:34  1500  Intel Corporation 82540EM Gigabit Ethernet Controller
    nic_list_lines = raw.split('\n')[2:]

    for nic_line in [line for line in nic_list_lines if len(line)]:
        vnic_dict = {}
        line_elements = nic_line.split()
        vnic_dict["name"] = line_elements[0]
        vnic_dict["pci_id"] = line_elements[1]
        vnic_dict["driver"] = line_elements[2]
        vnic_dict["admin_status"] = line_elements[3].lower()
        vnic_dict["link_status"] = line_elements[4].lower()
        vnic_dict["speed"] = int(line_elements[5])
        vnic_dict["duplex"] = line_elements[6].lower()
        vnic_dict["mac_address"] = line_elements[7]
        vnic_dict["mtu"] = int(line_elements[8])
        vnic_dict["description"] = ' '.join(line_elements[9:])
        vnics_list.append(vnic_dict)

    return vnics_list


def poll_for_dhcp_lease():
    for i in range(60):
        try:
            lines = run_cmd(["esxcli", "network", "ip", "interface", "ipv4", "get", "-i", "vmk0"]).decode().split('\n')
            if len(lines) >= 3:
                vmk0_ip_settings = lines[2].split()
                if len(vmk0_ip_settings) == 7 and vmk0_ip_settings[4] == 'DHCP':
                    return
            time.sleep(float(i))
        except subprocess.CalledProcessError:
            pass

    raise TimeoutError("No valid DHCP lease was received, aborting")


def get_metadata_service_address():
    with open('/var/lib/dhcp/dhclient-vmk0.leases', 'r') as dhcp_leases_file:
        dhcp_lines = dhcp_leases_file.readlines()
        classless_routes_list = list(filter(lambda line: re.search(CLASSLESS_ROUTE_PATTERN, line), dhcp_lines))

        if len(classless_routes_list):
            return re.search(CLASSLESS_ROUTE_PATTERN, classless_routes_list[-1].strip()).group(1)
        else:
            dhcp_identifier_list = list(filter(lambda line: re.search(DHCP_IDENTIFIER_PATTERN, line), dhcp_lines))
            return re.search(DHCP_IDENTIFIER_PATTERN, dhcp_identifier_list[-1].strip()).group(1)


def default_network_data():
    # "esxcli network nic list" fails time to time...
    for _ in range(60):
        try:
            vnics_by_pci_id = sorted(get_vnics_list(), key=lambda item: item["pci_id"])
            mac_address = vnics_by_pci_id[0]["mac_address"]
            break
        except subprocess.CalledProcessError:
            pass
    return {
        "links": [
            {
                "ethernet_mac_address": mac_address,
                "id": "mylink",
                "mtu": "1500",
            }
        ],
        "networks": [
            {
                "id": "network0",
                "link": "mylink",
                "type": "ipv4_dhcp"
            }
        ],
    }


def run_commands(commands):
    for c in commands:
        run_cmd(c, ignore_failure=True)


def main():
    logging.basicConfig(filename='/var/log/cloud-init.log',
                        filemode='w',
                        format='%(asctime)s %(levelname)s:%(message)s',
                        level=logging.DEBUG)
    # See: https://github.com/ansible-collections/community.vmware/issues/144
    localhost_over_ipv4()
    turn_tally2_off()

    cdrom_dev = find_cdrom_dev()
    if cdrom_dev:
        run_cmd(['vmkload_mod', 'iso9660'])
        mount_cdrom(cdrom_dev)
        try:
            set_network(load_network_data())
        except subprocess.CalledProcessError as error:
            logging.error(f"Failed executing command: {error}")
    else:
        try:
            set_network(default_network_data())
        except subprocess.CalledProcessError as error:
            logging.error(f"Failed executing command: {error}")

    meta_data = load_meta_data()
    user_data = load_user_data()

    hostname = user_data.get('fqdn') or user_data.get('hostname') or meta_data.get('hostname')
    if hostname:
        set_hostname(hostname)
    if 'public_keys' in meta_data:
        set_ssh_keys(meta_data.get('public_keys'))
    if 'admin_pass' in meta_data:
        set_root_pw(meta_data['admin_pass'])
    if 'password' in user_data:
        set_root_pw(user_data['password'])

    enable_ssh()
    turn_off_firewall()
    allow_nested_vm()
    restart_service('hostd')
    restart_service('vpxa')
    turn_tally2_off()
    create_local_datastore()
    run_commands(user_data.get("runcmd", []))

    if cdrom_dev:
        umount_cdrom(cdrom_dev)
        run_cmd(['vmkload_mod', '-u', 'iso9660'])


if __name__ == "__main__":
    main()
