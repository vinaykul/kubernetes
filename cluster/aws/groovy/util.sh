#!/bin/bash

# Copyright 2020 Authors of Arktos.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

SSH_USER=${KUBE_SSH_USER:-ubuntu}

# Detects the AMI to use for ubuntu (considering the region)
#
# Vars set:
#   AWS_IMAGE
function detect-groovy-image () {
  # This is the ubuntu 20.10 image for <region>, amd64, hvm:ebs-ssd
  # See here: http://cloud-images.ubuntu.com/locator/ec2/ for other images
  # This will need to be updated from time to time as amis are deprecated
  if [[ -z "${AWS_IMAGE-}" ]]; then
    case "${AWS_REGION}" in
      us-east-1)
        AWS_IMAGE=ami-041ba027e6cfd5da6
        ;;

      us-east-2)
        AWS_IMAGE=ami-0823b5cf95e3271bd
        ;;

      us-west-1)
        AWS_IMAGE=ami-01454e475267c91c4
        ;;

      us-west-2)
        AWS_IMAGE=ami-0a6a636facee14f3b
        ;;

      *)
        echo "Please specify AWS_IMAGE directly (region ${AWS_REGION} not recognized)"
        exit 1
    esac
  fi
}

