terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.74.0"
    }
  }
}

provider "aws" {
  profile = "js"   # aws 계정명
  region  = "ap-northeast-2"   # 리전
}


# vpc
resource "aws_vpc" "project_vpc" {
    cidr_block = "192.168.0.0/16"

    tags = {
        Name = "project_vpc"
    }
}

# subnet (public)
resource "aws_subnet" "public_subnet_1a" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.10.0/24"
    availability_zone = "ap-northeast-2a"
    map_public_ip_on_launch = true
    tags = {
        Name = "public_subnet_1a"
    }
}

resource "aws_subnet" "public_subnet_1c" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.30.0/24"
    availability_zone = "ap-northeast-2c"
    map_public_ip_on_launch = true
    tags = {
        Name = "public_subnet_1c"
    }
}

# subnet (private 1)
resource "aws_subnet" "private_subnet_2a" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.11.0/24"
    availability_zone = "ap-northeast-2a"
    tags = {
        Name = "private_subnet_2a"
    }
}


resource "aws_subnet" "private_subnet_2c" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.31.0/24"
    availability_zone = "ap-northeast-2c"
    tags = {
        Name = "private_subnet_2c"
    }
}

# subnet (private 2)
resource "aws_subnet" "private_subnet_3a" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.12.0/24"
    availability_zone = "ap-northeast-2a"
    tags = {
        Name = "private_subnet_3a"
    }
}


resource "aws_subnet" "private_subnet_3c" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.32.0/24"
    availability_zone = "ap-northeast-2c"
    tags = {
        Name = "private_subnet_3c"
    }
}

# subnet (database)
resource "aws_subnet" "database_subnet_4a" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.13.0/24"
    availability_zone = "ap-northeast-2a"
    map_public_ip_on_launch = false  # 데이터베이스 서브넷은 퍼블릭 IP를 할당하지 않음 (private 서브넷)
    tags = {
        Name = "database_subnet_4a"
    }
}

resource "aws_subnet" "database_subnet_4c" {
    vpc_id     = aws_vpc.project_vpc.id
    cidr_block = "192.168.33.0/24"
    availability_zone = "ap-northeast-2c"
    map_public_ip_on_launch = false  # 데이터베이스 서브넷은 퍼블릭 IP를 할당하지 않음 (private 서브넷)
    tags = {
        Name = "database_subnet_4c"
    }
}

# internet gateway 생성
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.project_vpc.id

  tags = {
    Name = "igw"
  }
}

# Public route table 생성
resource "aws_route_table" "public_route_table" {
  vpc_id = aws_vpc.project_vpc.id
  tags = {
    Name = "public-route-table"
  }
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id # 인터넷 게이트웨이 연결
  }
}

# Public subnet에 route table 연결
resource "aws_route_table_association" "public_subnet_association_1" {
  subnet_id      = aws_subnet.public_subnet_1a.id
  route_table_id = aws_route_table.public_route_table.id
}

resource "aws_route_table_association" "public_subnet_association_2" {
  subnet_id      = aws_subnet.public_subnet_1c.id
  route_table_id = aws_route_table.public_route_table.id
}

# cidr_blocks 수정하기
resource "aws_security_group" "public_ec2_sg" {
  name        = "public_ec2_sg"
  description = "public_ec2_sg"
  vpc_id      = aws_vpc.project_vpc.id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    "Name" = "tf_public_ec2_sg"
  }
}

resource "aws_eip" "nat_1" {
  vpc = true
}

resource "aws_eip" "nat_2" {
  vpc = true
}

resource "aws_nat_gateway" "nat_gw_1a" {
  allocation_id = aws_eip.nat_1.id
  subnet_id = aws_subnet.public_subnet_1a.id
}
resource "aws_nat_gateway" "nat_gw_1c" {
  allocation_id = aws_eip.nat_2.id
  subnet_id = aws_subnet.public_subnet_1c.id
}


##private
# private route table 1 생성
resource "aws_route_table" "web_private_route_table"{
  vpc_id = aws_vpc.project_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw_1a.id
  }
  tags = {
    Name = "web_private_route_table"
  }
}

resource "aws_route_table_association" "web_private_association_1" {
  route_table_id = aws_route_table.web_private_route_table.id
  subnet_id = aws_subnet.private_subnet_2a.id
}
resource "aws_route_table_association" "web_private_association_2" {
  route_table_id = aws_route_table.web_private_route_table.id
  subnet_id = aws_subnet.private_subnet_2c.id
}

# private route table 2 생성
resource "aws_route_table" "app_private_route_table"{
  vpc_id = aws_vpc.project_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw_1c.id  # 변경
  }
  tags = {
    Name = "app_private_route_table"
  }
}

resource "aws_route_table_association" "app_private_association_1" {
  route_table_id = aws_route_table.app_private_route_table.id
  subnet_id = aws_subnet.private_subnet_3a.id
}
resource "aws_route_table_association" "app_private_association_2" {
  route_table_id = aws_route_table.app_private_route_table.id
  subnet_id = aws_subnet.private_subnet_3c.id
}


# database route table
resource "aws_route_table" "db_private_route_table" {
  vpc_id = aws_vpc.project_vpc.id

  route {
    cidr_block        = "0.0.0.0/0"
    nat_gateway_id    = aws_nat_gateway.nat_gw_1a.id  # NAT Gateway 설정
  }

  tags = {
    Name = "db_private_route_table"
  }
}


resource "aws_route_table_association" "db_private_association_1" {
  route_table_id = aws_route_table.db_private_route_table.id
  subnet_id = aws_subnet.database_subnet_4a.id
}
resource "aws_route_table_association" "db_private_association_2" {
  route_table_id = aws_route_table.db_private_route_table.id
  subnet_id = aws_subnet.database_subnet_4c.id
}

# web server
resource "aws_instance" "terraform_private_web1" {
  tags = {
    Name = "terraform-private-web1"
  }
  ami           = "ami-040c33c6a51fd5d96" #ubuntu image
  instance_type = "t2.micro"
  key_name      = "Web-Key"
  vpc_security_group_ids = [aws_security_group.public_ec2_sg.id]
 subnet_id              = aws_subnet.private_subnet_2a.id

  associate_public_ip_address = true
}

resource "aws_instance" "terraform_private_web2" {
  tags = {
    Name = "terraform-private-web2"
  }
  ami           = "ami-040c33c6a51fd5d96" #ubuntu image
  instance_type = "t2.micro"
  key_name      = "Web-Key"
  vpc_security_group_ids = [aws_security_group.public_ec2_sg.id]
  subnet_id              = aws_subnet.private_subnet_2c.id

  associate_public_ip_address = true
}


# Web서버 SG
resource "aws_security_group" "web_elb_sg" {
  name        = "web-elb-sg"
  description = "web-elb-sg"
  vpc_id      = aws_vpc.project_vpc.id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "Name" = "web-elb-sg"
  }
}



# Application Load Balancer
resource "aws_lb" "private_web_lb" {
  name               = "private-web-lb"
  internal           = false
  load_balancer_type = "application"  # AWS 로드 밸런서의 유형을 지정
  security_groups    = [aws_security_group.web_elb_sg.id]
  subnets = [   # elb가 위치할 곳
    aws_subnet.public_subnet_1a.id,
    aws_subnet.public_subnet_1c.id
  ]

  tags = {
    Name = "private-web-lb"
  }
}

resource "aws_lb" "private_app_lb" {
  name               = "private-app-lb"
  internal           = true
  load_balancer_type = "application"  # AWS 로드 밸런서의 유형을 지정
  security_groups    = [aws_security_group.web_elb_sg.id]
  subnets = [   # elb가 위치할 곳
    aws_subnet.private_subnet_2a.id,
    aws_subnet.private_subnet_2c.id
  ]

  tags = {
    Name = "private-app-lb"
  }
}

# ALB TG : LB의 대상
resource "aws_lb_target_group" "private_web_lb_tg" {
  name     = "private-web-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.project_vpc.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }
}

resource "aws_lb_target_group" "private_app_lb_tg" {
  name     = "private-app-lb-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.project_vpc.id

  health_check {
    path                = "/"
    protocol            = "HTTP"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 3
    unhealthy_threshold = 2
  }
}

#--수정
resource "aws_lb_target_group_attachment" "private_web_lb_tg_attach_10" {
  target_group_arn = aws_lb_target_group.private_web_lb_tg.arn
  target_id        = aws_instance.terraform_private_web1.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "private_web_lb_tg_attach_30" {
  target_group_arn = aws_lb_target_group.private_web_lb_tg.arn
  target_id        = aws_instance.terraform_private_web2.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "private_app_lb_tg_attach_11" {
  target_group_arn = aws_lb_target_group.private_app_lb_tg.arn
  target_id        = aws_instance.terraform_private_app1.id
  port             = 8080
}

resource "aws_lb_target_group_attachment" "private_app_web_lb_tg_attach_31" {
  target_group_arn = aws_lb_target_group.private_app_lb_tg.arn
  target_id        = aws_instance.terraform_private_app2.id
  port             = 8080
}

#------------app-server-----------------------#
# app server
resource "aws_instance" "terraform_private_app1" {
  tags = {
    Name = "terraform-private-app1"
  }
  ami           = "ami-040c33c6a51fd5d96" #ubuntu image
  instance_type = "t2.micro"
  key_name      = "Web-Key"
  vpc_security_group_ids = [aws_security_group.web_elb_sg.id]
  subnet_id              = aws_subnet.private_subnet_2a.id

  associate_public_ip_address = true
}

resource "aws_instance" "terraform_private_app2" {
  tags = {
    Name = "terraform-private-app2"
  }
  ami           = "ami-040c33c6a51fd5d96" #ubuntu image
  instance_type = "t2.micro"
  key_name      = "Web-Key"
  vpc_security_group_ids = [aws_security_group.web_elb_sg.id]
  subnet_id              = aws_subnet.private_subnet_2c.id

  associate_public_ip_address = true
}



# ALB Listener (80->443 redirection)
resource "aws_lb_listener" "web_lb_listener_80" {
  load_balancer_arn = aws_lb.private_web_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}
resource "aws_lb_listener" "app_lb_listener_80" {
  load_balancer_arn = aws_lb.private_app_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"

    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

data "aws_acm_certificate" "server_cert" {
  domain   = "kyes30.click"
  statuses = ["ISSUED"]
}

data "aws_route53_zone" "web_kyes30_link" {
  name = "kyes30.click."
}


resource "aws_lb_listener" "web_lb_listener_443" {
  load_balancer_arn = aws_lb.private_web_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = data.aws_acm_certificate.server_cert.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.private_web_lb_tg.arn
  }
}
resource "aws_lb_listener" "app_lb_listener_443" {
  load_balancer_arn = aws_lb.private_app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn = data.aws_acm_certificate.server_cert.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.private_app_lb_tg.arn
  }
}


# DB Subnet Group
# RDS SG
# RDS 인스턴스 설정 
# DNS, CDN route53 설정
# ACM 인증서 조회
# Route 53 A 레코드 생성 - ALB와 연결




# Bastion Host Instance 테스트용


