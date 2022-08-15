# Gemnasium

A scanner that finds vulnerabilties in the [gitlab advisory database](https://gitlab.com/gitlab-org/advisories-community) aslo known as gemnasium 

## Required Tools

- ruby with the semver_dialects gem installed
- `gem install semver_dialects`

##  Required Dependencies

- cvss
- pyYaml
- requests

## Notes 

This uses the [MIT licensed version of the gemnasium database](https://gitlab.com/gitlab-org/advisories-community).
This can be set to the full version by setting the environment variable `GEMNASIUM_DATABASE_ZIP` to `https://gitlab.com/gitlab-org/security-products/gemnasium-db/-/archive/master/gemnasium-db-master.zip`
Note this can only be done with the explicit permission of Gitlab.  It violates their terms of use to use that database as part of a 3rd party tool. 
We should contact gitlab for permission to use this for internal use.