## Installation

hoppr-cop is available as a python module.

### Prerequisites

#### Note python 3.10 is required
The remaining prerequisites are optional, if not performed that scanner will not be activated.

1. [Install grype](https://github.com/anchore/grype#installation) `curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin`
2. [Install trivy](https://aquasecurity.github.io/trivy/v0.31.2/getting-started/installation/) `curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.31.2`
3. Register for a [free account with OSS-Index](https://ossindex.sonatype.org/user/register)
    1. Get the api token from your account page.  Export your username and token as `OSS_INDEX_TOKEN` and `OSS_INDEX_USER`

### Install Python Module

#### Note python 3.10 is required to install the tool

` pip install hoppr-cop --extra-index-url https://gitlab.com/api/v4/projects/38643089/packages/pypi/simple`

### Usage

Note the first time you run the command each day can be quite slow as it downloads the databases.  Subsequent runs should be much more performant.

![](usage.png)

## Contributing

See the [Contribution Guidelines](contributing.md)
