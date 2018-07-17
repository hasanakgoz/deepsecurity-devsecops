# deepsecurity-ansible-playbooks
Ansible Playbooks for the Deep Security Ansible Role

Deep Security Ansible Playbooks
====

All work in progress
   
## Usage examples
Create some EC2 instances<br/>
ansible-playbook ec2_create_instances.yml<br/>
<br/>
Install Deep Security Angent and prepare for facter<br/>
ansible-playbook ds_agent_facter_install.yml<br/>
<br/>
Set Deep Security Policy by Name<br/>
ansible-playbook ds_set_policy.yml<br/>
<br/>
Install Apache and set appropriate Deep Security Policy<br/>
ansible-playbook s-apache2_install_set.yml --extra-vars="private_ip=<TARGET NODE>"<br/>
<br/>
Install Apache and modify actual Deep Security Policy<br/>
ansible-playbook s-apache2_install_modify.yml --extra-vars="private_ip=<TARGET NODE>"<br/>
<br/>
Query CVE and MS vulnerability protection by Deep Security<br/>
ansible-playbook s-ds_protection_status.yml --extra-vars="private_ip=<TARGET NODE>"<br/>
<br/>
Query Deep Security Agent status<br/>
ansible <TARGET NODE> -m setup -a "filter=ansible_local"<br/>

