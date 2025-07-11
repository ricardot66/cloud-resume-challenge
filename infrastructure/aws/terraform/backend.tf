terraform {
  cloud {
    organization = "ricardo-cloud-resume"

    workspaces {
      name = "aws-resume-infrastructure"
    }
  }
}
