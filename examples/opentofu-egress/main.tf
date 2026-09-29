terraform {
  required_version = ">= 1.10.0, < 2.0.0"

  required_providers {
    http = {
      source  = "hashicorp/http"
      version = "= 3.6.1"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = "= 3.0.0"
    }
  }
}

variable "fixture_url" {
  type = string
}

variable "fixture_token" {
  type      = string
  sensitive = true
}

provider "restapi" {
  uri                  = var.fixture_url
  bearer_token         = var.fixture_token
  insecure             = true
  write_returns_object = true
  id_attribute         = "id"
}

data "http" "health" {
  url      = "${var.fixture_url}/health"
  insecure = true
  request_headers = {
    Authorization = "Bearer ${var.fixture_token}"
  }
}

resource "restapi_object" "record" {
  path = "/records"
  data = jsonencode({ id = "proofbound-fixture", value = "applied" })
}

output "health_body" {
  value = data.http.health.response_body
}

output "record_id" {
  value = restapi_object.record.id
}
