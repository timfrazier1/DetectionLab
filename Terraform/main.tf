# Specify the provider and access details
provider "aws" {
  shared_credentials_file = var.shared_credentials_file
  region                  = var.region
  profile                 = var.profile
}

# Create a VPC to launch our instances into
resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"
}

# Create an internet gateway to give our subnet access to the outside world
resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.default.id
}

# Grant the VPC internet access on its main route table
resource "aws_route" "internet_access" {
  route_table_id         = aws_vpc.default.main_route_table_id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.default.id
}

# Create a subnet to launch our instances into
resource "aws_subnet" "default" {
  vpc_id                  = aws_vpc.default.id
  cidr_block              = "192.168.38.0/24"
  availability_zone       = var.availability_zone
  map_public_ip_on_launch = true
}

# Adjust VPC DNS settings to not conflict with lab
resource "aws_vpc_dhcp_options" "default" {
  domain_name          = "windomain.local"
  domain_name_servers  = concat([aws_instance.dc.private_ip], var.external_dns_servers)
  netbios_name_servers = [aws_instance.dc.private_ip]
}

resource "aws_vpc_dhcp_options_association" "default" {
  vpc_id          = aws_vpc.default.id
  dhcp_options_id = aws_vpc_dhcp_options.default.id
}

# Our default security group for the logger host
resource "aws_security_group" "logger" {
  name        = "logger_security_group"
  description = "DetectionLab: Security Group for the logger host"
  vpc_id      = aws_vpc.default.id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Splunk access
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Fleet access
  ingress {
    from_port   = 8412
    to_port     = 8412
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Allow all traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.38.0/24"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Our default security group for the Phantom host
resource "aws_security_group" "phantom" {
  name        = "phantom_security_group"
  description = "DetectionLab: Security Group for the phantom host"
  vpc_id      = aws_vpc.default.id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Web UI access
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Allow all traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.38.0/24"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "windows" {
  name        = "windows_security_group"
  description = "DetectionLab: Security group for the Windows hosts"
  vpc_id      = aws_vpc.default.id

  # RDP
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # WinRM
  ingress {
    from_port   = 5985
    to_port     = 5986
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Windows ATA
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }

  # Allow all traffic from the private subnet
  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["192.168.38.0/24"]
  }

  # outbound internet access
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_key_pair" "auth" {
  key_name   = var.public_key_name
  public_key = file(var.public_key_path)
}

resource "aws_instance" "phantom" {
  instance_type = "t2.medium"
  ami           = coalesce(var.phantom_ami, data.aws_ami.phantom_ami.image_id)

  tags = {
    Name = "Phantom 4.5"
  }
#  ami = "ami-081754fc6dc359927"

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.phantom.id]
  key_name               = aws_key_pair.auth.key_name
  private_ip             = "192.168.38.110"

  provisioner "remote-exec" {
    inline = [
      "echo ${aws_instance.phantom.id} > phantom_instance_id.txt",
      "which psql >> output1.txt",
      "sleep 480",
      "which psql >> output2.txt",
      "sudo psql -d phantom -c 'select key from token where id=1;' | grep = | sed 's/^[[:space:]]*//g' > token.txt",
      "sudo curl -ku admin:password https://localhost/rest/ph_user/2 -d '{\"first_name\":\"'$(cat token.txt)'\", \"default_label\": \"advsim_test\"}'",
      "sudo psql -d phantom -c \"update token set allowed_ips = '[\\\"any\\\"]';\"",
      "sudo psql -d phantom -c 'select * from token;' > token_table.txt",
      "sudo psql -d phantom -c \"insert into scm(branch, disabled, name, read_only, type, uri, version) VALUES ('master', 'f', 'AdvSim', 'f','git','https://github.com/timfrazier1/AdvSimPlaybooks.git',1);\"",
      "cat token.txt",
      "sudo git clone https://github.com/timfrazier1/AdversarySimulation.git /opt/AdversarySimulation",
      "sleep 120",
      "sudo python /opt/AdversarySimulation/resources/install_phantom_app.py /opt/AdversarySimulation/resources/phantom_apps/phatomicredteam.tgz password",
      "sudo python /opt/AdversarySimulation/resources/install_phantom_app.py /opt/AdversarySimulation/resources/phantom_apps/phwinrm.tgz password",
      "sudo curl -ku admin:password https://localhost/rest/asset -d '{\"configuration\": {\"verify_cert\": true, \"base_url\": \"https://github.com/redcanaryco/atomic-red-team.git\"}, \"name\": \"art_main_repo\", \"product_name\": \"Atomic Red Team\", \"product_vendor\": \"Red Canary\"}'",
      "sudo curl -ku admin:password https://localhost/rest/container -d '{\"label\": \"events\", \"name\": \"Example Container\"}'",
      "sudo curl -ku admin:password https://localhost/rest/app?_filter_name__contains=%22Atomic%22 | python -c \"import sys,json; print json.load(sys.stdin)['data'][0]['id']\" > app_id.txt",
      "sudo curl -ku admin:password https://localhost/rest/action_run -d '{\"action\": \"test connectivity\", \"container_id\": 1, \"name\": \"art_test_connectivity\", \"targets\": [{\"assets\": [\"art_main_repo\"], \"parameters\": [], \"app_id\": '$(cat app_id.txt)'}]}'",
      "sleep 120",
      "sudo curl -ku admin:password https://localhost/rest/asset -d '{\"name\": \"winrm_dect_lab\", \"product_name\": \"Windows Remote Management\", \"product_vendor\": \"Microsoft\", \"configuration\": {\"username\": \"vagrant\", \"domain\": \"\", \"endpoint\": \"192.168.38.104\", \"verify_server_cert\": false, \"default_port\": \"5985\", \"default_protocol\": \"http\", \"password\": \"vagrant\", \"transport\": \"ntlm\"}}'",
      "sudo curl -ku admin:password https://localhost/rest/asset -d '{\"name\": \"splunk_dect_lab\", \"product_vendor\": \"Splunk Inc.\", \"product_name\": \"Splunk Enterprise\", \"configuration\": {\"username\": \"admin\", \"max_container\": 100, \"ingest\": {\"container_label\": \"splunk_events\", \"start_time_epoch_utc\": null}, \"retry_count\": \"3\", \"verify_server_cert\": false, \"device\": \"192.168.38.105\", \"timezone\": \"UTC\", \"password\": \"changeme\", \"port\": \"8089\"}}'",
      "sudo curl -ku admin:password https://localhost/rest/scm?_filter_name=%22AdvSim%22 | python -c \"import sys,json; print json.load(sys.stdin)['data'][0]['id']\" > repo_id.txt",
      "sudo curl -ku admin:password https://localhost/rest/scm/$(cat repo_id.txt) -d '{\"pull\": true, \"force\": true}'",
      "sudo curl -ku admin:password https://localhost/rest/playbook?_filter_name=%22Modular%20Simulation%22 | python -c \"import sys,json; print json.load(sys.stdin)['data'][0]['id']\" > playbook_id.txt",
      "sudo curl -ku admin:password https://localhost/rest/playbook/$(cat playbook_id.txt) -d '{\"active\": true, \"cancel_runs\": true}'",
      "sudo curl -ku admin:password https://localhost/rest/ph_user/2 -d '{\"first_name\":\"'$(cat token.txt)'\", \"default_label\": \"advsim_test\"}'",
    ]

    connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = "centos"
      private_key = file(var.private_key_path)
    }
  }

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "logger" {
  instance_type = "t2.medium"
  ami           = coalesce(var.logger_ami, data.aws_ami.logger_ami.image_id)

  tags = {
    Name = "logger"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.logger.id]
  key_name               = aws_key_pair.auth.key_name
  private_ip             = "192.168.38.105"

  # Provision the AWS Ubuntu 16.04 AMI from scratch.
  # Provision the AWS Ubuntu 16.04 AMI from scratch.
  provisioner "remote-exec" {
    inline = [
      "echo ${aws_instance.phantom.id} > phantom_instance_id.txt",
      "cat phantom_instance_id.txt",
      "curl -ku admin:password https://192.168.38.110/rest/ph_user/2 | cut -d\":\" -f 10 | cut -d'\"' -f 2 > phantom_token.txt",
      "cat phantom_token.txt",
      "cat phantom_token.txt | sed -e \"s/=/%3D/g\" | sed -e \"s/+/%2B/g\" | sed -e \"s/\\//%2F/g\" > url_phantom_token.txt",
      "cat url_phantom_token.txt",
      "sudo add-apt-repository universe && sudo apt-get -qq update && sudo apt-get -qq install -y git",
      "echo 'logger' | sudo tee /etc/hostname && sudo hostnamectl set-hostname logger",
      "sudo adduser --disabled-password --gecos \"\" vagrant && echo 'vagrant:vagrant' | sudo chpasswd",
      "sudo mkdir /home/vagrant/.ssh && sudo cp /home/ubuntu/.ssh/authorized_keys /home/vagrant/.ssh/authorized_keys && sudo chown -R vagrant:vagrant /home/vagrant/.ssh",
      "echo 'vagrant    ALL=(ALL:ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
      "sudo git clone https://github.com/timfrazier1/AdversarySimulation.git /opt/AdversarySimulation",
      "sudo git clone https://github.com/timfrazier1/DetectionLab.git /opt/DetectionLab",
      "sudo sed -i 's/eth1/eth0/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's/ETH1/ETH0/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's#/usr/local/go/bin/go get -u#GOPATH=/root/go /usr/local/go/bin/go get -u#g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's#/vagrant/resources#/opt/DetectionLab/Vagrant/resources#g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo chmod +x /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo apt-get -qq update",
      "sudo /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo curl -ku admin:changeme https://localhost:8089/servicesNS/nobody/phantom/update_phantom_config\\?output_mode\\=json -d '{\"verify_certs\":\"false\",\"enable_logging\":\"true\",\"config\":[{\"ph-auth-token\":\"'$(cat url_phantom_token.txt)'\",\"server\":\"https://192.168.38.110\",\"custom_name\":\"DectLab Phantom\",\"default\":true,\"user\":\"automation\",\"ph_auth_config_id\":\"k141js0d\",\"proxy\":\"\",\"validate\":true}],\"accepted\":\"true\",\"save\":true}'",
      "sudo curl -ku admin:password https://192.168.38.110/rest/ph_user/2 -d '{\"first_name\": \"\"}'",
      
    ]

    connection {
      host        = coalesce(self.public_ip, self.private_ip)
      type        = "ssh"
      user        = "ubuntu"
      private_key = file(var.private_key_path)
    }
  }

  root_block_device {
    delete_on_termination = true
    volume_size           = 64
  }
}

resource "aws_instance" "dc" {
  instance_type = "t2.medium"

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.dc_ami, data.aws_ami.dc_ami.image_id)

  tags = {
    Name = "dc.windomain.local"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.102"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "wef" {
  instance_type = "t2.medium"

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.wef_ami, data.aws_ami.wef_ami.image_id)

  tags = {
    Name = "wef.windomain.local"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.103"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "win10" {
  instance_type = "t2.medium"

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.win10_ami, data.aws_ami.win10_ami.image_id)

  tags = {
    Name = "win10.windomain.local"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.104"

  root_block_device {
    delete_on_termination = true
  }
}

