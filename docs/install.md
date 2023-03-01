# Installation

hoppr-cop is available as a python module or a docker image 

## Quick Install with Docker (recommended)

Register for a [free account with OSS-Index](https://ossindex.sonatype.org/user/register).
Then get the api token from your account page.  You will use these in the next step.  

Add the following to your `~/.bashrc` file
```shell
export OSS_INDEX_USER=<your email>
export OSS_INDEX_TOKEN=<your token> 
export CACHE_DIR=/tmp
export HOPPR_COP_VERSION="latest"

alias hoppr-cop='docker run -v $(pwd):/hoppr  -e OSS_INDEX_TOKEN -e OSS_INDEX_USER -v $CACHE_DIR:/cache  -t registry.gitlab.com/hoppr/hoppr-cop/hoppr-cop:$HOPPR_COP_VERSION'
```

Test the installation by running `hoppr-cop --help`

## Gitlab CI Usage

```yaml
variables: 
   HOPPR_COP_TAG: latest
   SBOM_FILE: bom.json
   OSS_INDEX_TOKEN: token
   OSS_INDEX_USER: user
   
   
hoppr-cop:
  image:
    name:  registry.gitlab.com/hoppr/hoppr-cop/hoppr-cop:$HOPPR_COP_TAG
    entrypoint: [""]
  stage: build
  script:
     - hoppr-cop --format table  --format html --format gilab --output-dir ./vuln-reports  $SBOM_FILE 
- artifacts:
    paths:
      - vuln-reports/*
    reports:
        dependency_scanning: vuln-reports/gl-dependency-scanning-report.json
```

## Full install (pip)

### Prerequisites

#### Note python 3.10 is required
The remaining prerequisites are optional, if not performed that scanner will not be activated.

1. [Install grype](https://github.com/anchore/grype#installation) `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`
2. [Install trivy](https://aquasecurity.github.io/trivy/v0.31.2/getting-started/installation/) `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.31.2`
3. Register for a [free account with OSS-Index](https://ossindex.sonatype.org/user/register)
    1. Get the api token from your account page.  Export your username and token as `OSS_INDEX_TOKEN` and `OSS_INDEX_USER`
4. install `ruby`
5. run `gem install semver_dialects`

### Install Python Module

#### Note python 3.10 is required to install the tool

`pip install hoppr-cop`

