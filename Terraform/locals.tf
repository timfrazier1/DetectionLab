locals {
  fleet_url     = "https://${aws_instance.logger.public_ip}:8412"
  splunk_url    = "https://${aws_instance.logger.public_ip}:8000"
  ata_url       = "https://${aws_instance.wef.public_ip}"
  guacamole_url = "http://${aws_instance.logger.public_ip}:8080/guacamole"
  phantom_url   = "https://${aws_instance.phantom.public_ip}"
  phantom_instance_id = "${aws_instance.phantom.id}"
}

