# Deploy Scripts for OSIRAA test environment

This directory contains [Ansible](ansible.com) playbooks for deploying the DRP reference Authorized Agent and an open source privacy compliance stack implementing the Privacy Infrastructure Provider interfaces, Ethyca's [FidesOps](https://ethyca.github.io/fidesops/) and [fidesdemo](https://github.com/ethyca/fidesdemo) application.

## Deploying OSIRAA test environment

These Ansible playbooks will deploy OSIRAA and fidesops on to an Ubuntu 22.04 LTS instance running on AWS. It may be adaptable to other systems and other operating systems but YMMV.

### Configure Instance Access

Upload an SSH key or generate one which can be attached to a fresh compute instance. This can be done through the AWS EC2 console *EC2 console sidebar -> Network & Security -> Key Pairs*: https://us-east-1.console.aws.amazon.com/ec2/home?region=us-east-1#KeyPairs:

One of these will be used to establish initial access to the instance, but more users' keys will be specified in the deploy script. Add other SSH keys to ./files/keys/ and reference them in the `install SSH keys` task in `drp.yml`. Remove the authors' keys if you're not deploying this for Consumer Reports!

### Launch and Configure instance

Launch an AWS `t2.medium` instance or equivalent; you can down-size this later but building containers on small hosts can be arduous. These scripts were tested against **Ubuntu 22.04 LTS**.

Attach an Elastic IP or equivalent to it so that there is a consistent IPv4 address for the server.
Record the instance IP address in the file `inventory` in this repository.

TODO: reason about and document letsencrypt/route53/SSL support

Run `ssh-copy-id ubuntu@$YOUR_INSTANCE_IP` to ensure you can SSH to the instance without prompting for passwords; ansible uses SSH to run commands on the remote instance. Note that the keypairs configured above should "just work" but this may keep you from having other issues from cropping up.

Configure the instance to have a security group which allows access to the following TCP ports:
- basic access ports
  - 22
  - 443
  - 80
- fidesops
  - 3000
  - 4000
  - 8080
  - 9090
- osiraa
  - 8000

# Running the scripts

Once your AWS instance is running, it's time to deploy software to it

* Install [Ansible](ansible.com) to your local system.
* Run `ansible-playbook -i inventory drp.yml`

After this completes successfully you should be able to browse to the AWS instance's port 8000 and see OSIRAA running on it. SSH to the instance and run `cd osiraa && docker compose run web python manage.py createsuperuser` to set up access to the Django admin panel running on `:8000/admin` to configure your test endpoints and the like.

