variable "aws_region" {
  description = "The AWS region to deploy the resources in."
  type        = string
}

variable "instance_name" {
  description = "The base name for the Splunk instances."
  type        = string
}

variable "instance_type" {
  description = "The instance type for the Splunk servers."
  type        = string
  default     = "t3.medium"
}

variable "storage_size" {
  description = "The size of the root volume for the instances."
  type        = number
  default     = 30
}

variable "usermail" {
  description = "The email of the user creating the infrastructure."
  type        = string
}

variable "quotahours" {
  description = "Run quota hours for the instances."
  type        = number
}

variable "category" {
  description = "Category tag for the instance group."
  type        = string
}

variable "planstartdate" {
  description = "Plan start date tag for the instance group."
  type        = string
}

variable "hoursperday" {
  type        = string
}

variable "key_name" {
  description = "Base key name to generate unique keys."
  type        = string
}

variable "splunk_license_url" {
  type        = string
}
