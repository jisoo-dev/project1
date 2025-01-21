provider "aws" {
  profile = "js"
  alias   = "global"
  region  = "us-east-1" # CloudFront 및 관련 리소스는 항상 글로벌 리전에서 관리
}


# Route 53 A 레코드 생성 - ALB와 연결
resource "aws_route53_record" "sub_alb_record" {
  zone_id = data.aws_route53_zone.web_kyes30_link.zone_id
  name    = "www.${data.aws_route53_zone.grb_hosted_zone.name}"
  type    = "A"

  alias {
    name                   = aws_lb.private_web_lb.domain_name
    zone_id                = aws_lb.private_web_lb.hosted_zone_id
    evaluate_target_health = true
  }

  allow_overwrite = true
}

resource "aws_route53_record" "cdn_record" {
  zone_id = data.aws_route53_zone.web_kyes30_link.zone_id 
  name    = "cdn.kyes30.click"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.cdn.domain_name
    zone_id                = aws_cloudfront_distribution.cdn.hosted_zone_id
    evaluate_target_health = false
  }
}



resource "aws_iam_policy" "waf_and_cloudfront_policy" {
  name        = "WAFAndCloudFrontPolicy"
  description = "Policy to allow WAF and CloudFront actions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "wafv2:AssociateWebACL",
          "cloudfront:CreateDistributionWithTags",
          "cloudfront:UpdateDistribution"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "cloudfront_waf_role" {
  name = "CloudFrontWAFRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "waf_and_cloudfront_policy_attachment" {
  policy_arn = aws_iam_policy.waf_and_cloudfront_policy.arn
  role       = aws_iam_role.cloudfront_waf_role.name
}

#----------------------------------------------
# 3. AWS WAF 생성: 두 개의 WAF(Web ACL)를 생성하여 다음과 같이 연결
# 
# CloudFront WAF

resource "aws_wafv2_web_acl" "cloudfront_waf" {
  provider = aws.global

  name        = "cloudfront-waf"
  description = "WAF for CloudFront"
  scope       = "CLOUDFRONT" # CloudFront용 WAF는 글로벌 범위이어야 함
  default_action {
    allow {}
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "cloudfront-waf"
    sampled_requests_enabled   = true
  }
}


resource "aws_cloudwatch_log_group" "waf_log_group" {
  name = "/aws/wafv2/logs/cloudfront-waf"
}


# ALB WAF 수정
resource "aws_wafv2_web_acl" "alb_waf" {
  name        = "alb-waf"
  description = "WAF for ALB"
  scope       = "REGIONAL" # ALB용 WAF는 지역 범위이어야 함(ALB와 같은 리소스에 사용됨)
  default_action {
    #WAF에 특정 규칙이 설정되지 않을 경우 트래픽을 차단할지 허용할지 결정
    allow {} #규칙에 매칭되지 않은 모든 요청을 허용함
  }
  visibility_config {
    #WAF의 모니터링 및 로그 설정
    cloudwatch_metrics_enabled = true #WAF 메트릭을 CloudWatch로 보냄
    metric_name                = "alb-waf" #CloudWatch에서 사용할 메트릭 이름
    sampled_requests_enabled   = true #WAF 규칙에 매칭된 샘플 요청을 기록
  }


    # web 취약점 방어(XSS 등)
    rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1 #rule 우선순위, 낮을수록 우선 적용됨

    #규칙 핵심, AWS에서 제공하는 규칙 그룹을 참조함
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet" #규칙 활성화함
        vendor_name = "AWS" #규칙을 제공하는 공급자 이름 설정
      }
    }

    #해당 규칙에 대해 별도의 동작을 덮어쓰지 않도록 설정
    override_action {
      none {} #기본 동작임(추가 허용이나 차단 변경하지 않음)
    }

    #규칙 가시성 설정
    visibility_config {
      cloudwatch_metrics_enabled = true #CloudWatch에서 메트릭 볼 수 있게 설정
      metric_name                = "AWSManagedRulesCommonRuleSet"
      sampled_requests_enabled   = true #CloudWatch에서 분석할 수 있게 설정
    }
  }

 
  # SQL Injection attack 방어
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesSQLiRuleSet"
      sampled_requests_enabled   = true
    }
  }

   # 관리자 인증 및 권한 악용 공격 차단
  rule {
    name     = "AWSManagedRulesAdminProtectionRuleSet"
    priority = 3

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesAdminProtectionRuleSet"
        vendor_name = "AWS"
      }
    }

    override_action {
      none {}
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "AWSManagedRulesAdminProtectionRuleSet"
      sampled_requests_enabled   = true
    }
  }
}

# main.tf와 중복 리스너를 생성하는 대신 리스너의 규칙이나 추가 동작을 정의합니다.
# HTTPS 리스너에 규칙 추가
resource "aws_lb_listener_rule" "waf_rule" {
  listener_arn = aws_lb_listener.web_lb_listener_443.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.private_web_lb_tg.arn
  }

  condition {
    path_pattern {
      values = ["/waf-protected/*"]  # 필요시 경로 조건 추가
    }
  }
}

resource "aws_wafv2_web_acl_association" "alb_waf_assoc" {
  resource_arn = aws_lb.private_web_lb.arn
  web_acl_arn  = aws_wafv2_web_acl.alb_waf.arn  # WAF Web ACL의 ARN
}




# ALB를 원본(origin)으로 설정
# CloudFront 생성: ALB를 원본으로 설정
# CloudFront 배포 수정

resource "aws_cloudfront_distribution" "cdn" {
  provider = aws.global

  origin {
    domain_name = aws_lb.private_web_lb.dns_name
    # domain_name = "test-alb-395659110.ap-northeast-2.elb.amazonaws.com"
    origin_id = "alb-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"

      origin_ssl_protocols = ["TLSv1.2"]
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
      locations        = [] # 필요 시 위치 추가
    }
  }

  default_cache_behavior {
    target_origin_id       = "alb-origin"
    viewer_protocol_policy = "redirect-to-https"

    allowed_methods = ["GET", "HEAD", "OPTIONS"]
    cached_methods  = ["GET", "HEAD"]

    forwarded_values {
      query_string = false # 쿼리 문자열 전달 여부
      cookies {
        forward = "none" # 쿠키 전달 여부 (all, none, 또는 whitelist)
      }
      # headers는 생략 (필요 시 추가)
    }
  }


  enabled             = true
  is_ipv6_enabled     = true
  comment             = "CloudFront Distribution for ALB"
  default_root_object = "index.html"

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  web_acl_id = aws_wafv2_web_acl.cloudfront_waf.arn # Web ACL 연결, id -> arn으로 변경함 
}



# Route53 레코드 생성: DNS 레코드를 통해 CloudFront를 통해 ALB로 트래픽이 흐르도록 설정.

