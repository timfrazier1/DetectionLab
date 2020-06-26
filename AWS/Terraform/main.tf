# Specify the provider and access details
provider "aws" {
  shared_credentials_file = var.shared_credentials_file
  region                  = var.region
  profile                 = var.profile
}

# Create a VPC to launch our instances into
resource "aws_vpc" "default" {
  cidr_block = "192.168.0.0/16"
  tags = var.custom-tags
}

# Create an internet gateway to give our subnet access to the outside world
resource "aws_internet_gateway" "default" {
  vpc_id = aws_vpc.default.id
  tags = var.custom-tags
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
  tags = var.custom-tags
}

# Adjust VPC DNS settings to not conflict with lab
resource "aws_vpc_dhcp_options" "default" {
  domain_name          = "windomain.local"
  domain_name_servers  = concat([aws_instance.dc.private_ip], var.external_dns_servers)
  netbios_name_servers = [aws_instance.dc.private_ip]
  tags = var.custom-tags
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
  tags = var.custom-tags

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

  # Guacamole access
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.ip_whitelist
  }
  ingress {
    from_port   = 8443
    to_port     = 8443
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
  tags = var.custom-tags

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
  tags = var.custom-tags
}

resource "aws_instance" "phantom" {
  instance_type = "t2.medium"
  ami           = coalesce(var.phantom_ami, data.aws_ami.phantom_ami.image_id)

  tags = {
    Name = "Phantom 4.8"
  }

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.phantom.id]
  key_name               = aws_key_pair.auth.key_name
  private_ip             = "192.168.38.110"

  provisioner "remote-exec" {
    inline = [
      "echo ${aws_instance.phantom.id} > phantom_instance_id.txt",
      "sleep 480",
      "which psql",
      "sudo psql -d phantom -c \"insert into scm(branch, disabled, name, read_only, type, uri, version) VALUES ('master', 'f', 'AdvSim', 'f','git','https://github.com/timfrazier1/AdvSimPlaybooks.git',1);\"",
      "sudo git clone https://github.com/timfrazier1/AdversarySimulation.git /opt/AdversarySimulation",
      "sleep 120",
      "python /opt/AdversarySimulation/resources/setup_phantom.py",
      "sudo sed -i 's/GSSAPIAuthentication yes/GSSAPIAuthentication no/g' /etc/ssh/sshd_config",
      "sudo sed -i 's/#UseDNS yes/UseDns no/g' /etc/ssh/sshd_config",
      "sudo /sbin/service sshd restart",
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
  instance_type = "t3.medium"
  ami           = coalesce(var.logger_ami, data.aws_ami.logger_ami.image_id)

  tags = merge(var.custom-tags, map(
    "Name", "${var.instance_name_prefix}logger"
  ))

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.logger.id]
  key_name               = aws_key_pair.auth.key_name
  private_ip             = "192.168.38.105"

  # Provision the AWS Ubuntu 18.04 AMI from scratch.
  provisioner "remote-exec" {
    inline = [
      "echo ${aws_instance.phantom.id} > phantom_instance_id.txt",
      "cat phantom_instance_id.txt",
      "curl -ku admin:password https://192.168.38.110/rest/ph_user/2/token | cut -d\":\" -f 2 | cut -d'\"' -f 2 > phantom_token.txt",
      "cat phantom_token.txt",
      "cat phantom_token.txt | sed -e \"s/=/%3D/g\" | sed -e \"s/+/%2B/g\" | sed -e \"s/\\//%2F/g\" > url_phantom_token.txt",
      "cat url_phantom_token.txt",
      "sudo apt-get -qq update && sudo apt-get -qq install -y git",
      "echo 'logger' | sudo tee /etc/hostname && sudo hostnamectl set-hostname logger",
      "sudo adduser --disabled-password --gecos \"\" vagrant && echo 'vagrant:vagrant' | sudo chpasswd",
      "sudo mkdir /home/vagrant/.ssh && sudo cp /home/ubuntu/.ssh/authorized_keys /home/vagrant/.ssh/authorized_keys && sudo chown -R vagrant:vagrant /home/vagrant/.ssh",
      "echo 'vagrant    ALL=(ALL:ALL) NOPASSWD:ALL' | sudo tee -a /etc/sudoers",
      "sudo git clone https://github.com/timfrazier1/AdversarySimulation.git /opt/AdversarySimulation",
      "sudo git clone https://github.com/timfrazier1/DetectionLab.git /opt/DetectionLab",
      "sudo sed -i 's/eth1/ens5/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's/ETH1/ens5/g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's/eth1/ens5/g' /opt/DetectionLab/Vagrant/resources/suricata/suricata.yaml",
      "sudo sed -i 's#/vagrant/resources#/opt/DetectionLab/Vagrant/resources#g' /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config",
      "sudo service ssh restart",
      "sudo chmod +x /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo apt-get -qq update",
      "sudo /opt/DetectionLab/Vagrant/bootstrap.sh",
      "sudo curl -ku admin:changeme https://localhost:8089/servicesNS/nobody/phantom/update_phantom_config\\?output_mode\\=json -d '{\"verify_certs\":\"false\",\"enable_logging\":\"true\",\"config\":[{\"ph-auth-token\":\"'$(cat url_phantom_token.txt)'\",\"server\":\"https://192.168.38.110\",\"custom_name\":\"DectLab Phantom\",\"default\":true,\"user\":\"automation\",\"ph_auth_config_id\":\"k141js0d\",\"proxy\":\"\",\"validate\":true}],\"accepted\":\"true\",\"save\":true}'",
      
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
  instance_type = "t3.medium"

  provisioner "remote-exec" {
    inline = [
      "choco install -force -y winpcap",
      "ipconfig /renew",
      "powershell.exe -c \"Add-Content 'c:\\windows\\system32\\drivers\\etc\\hosts' '        192.168.38.103    wef.windomain.local'\"",
      ]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.dc_ami, data.aws_ami.dc_ami.image_id)

  tags = merge(var.custom-tags, map(
    "Name", "${var.instance_name_prefix}dc.windomain.local"
  ))

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.102"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "wef" {
  instance_type = "t3.medium"

  provisioner "remote-exec" {
    inline = [
      "choco install -force -y winpcap",
      "powershell.exe -c \"Add-Content 'c:\\windows\\system32\\drivers\\etc\\hosts' '        192.168.38.102    dc.windomain.local'\"",
      "powershell.exe -c \"Add-Content 'c:\\windows\\system32\\drivers\\etc\\hosts' '        192.168.38.102    windomain.local'\"",
      "ipconfig /renew",
    ]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.wef_ami, data.aws_ami.wef_ami.image_id)

  tags = merge(var.custom-tags, map(
    "Name", "${var.instance_name_prefix}wef.windomain.local"
  ))

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.103"

  root_block_device {
    delete_on_termination = true
  }
}

resource "aws_instance" "win10" {
  instance_type = "t2.medium"

  provisioner "remote-exec" {
    inline = [
      "choco install -force -y winpcap",
      "powershell.exe -c \"Add-Content 'c:\\windows\\system32\\drivers\\etc\\hosts' '        192.168.38.102    dc.windomain.local'\"",
      "powershell.exe -c \"Add-Content 'c:\\windows\\system32\\drivers\\etc\\hosts' '        192.168.38.102    windomain.local'\"",
      "ipconfig /renew",
    ]

    connection {
      type     = "winrm"
      user     = "vagrant"
      password = "vagrant"
      host     = coalesce(self.public_ip, self.private_ip)
    }
  }

  # Uses the local variable if external data source resolution fails
  ami = coalesce(var.win10_ami, data.aws_ami.win10_ami.image_id)

  tags = merge(var.custom-tags, map(
    "Name", "${var.instance_name_prefix}win10.windomain.local"
  ))

  subnet_id              = aws_subnet.default.id
  vpc_security_group_ids = [aws_security_group.windows.id]
  private_ip             = "192.168.38.104"

  root_block_device {
    delete_on_termination = true
  }
}
