# Security Policy

## Supported Versions

Only the latest major release (x.y.z where x is the major release) is supported

## Reporting a Vulnerability

To report a security vulnerability please email [open.source@lmco.com](mailto:open.source@lmco.com)

## Steps We Have Taken To Ensure the Security of this Project 

The Security of this project is very important to us.  Here are some of the steps we have taken to ensure your security. 

* __2FA__ - All repositories in the LM orginazation require two factor authentication for all contributers. 
* [__OSSF Scorecard__](https://github.com/ossf/scorecard/blob/32d6ba27757fcaf6145b03195f84c74b311e4121/docs/checks.md) - We have enabled the OSSF scorecard action on the github mirror of this project and implemented all recomendations.  
* [![OSSF Security Best Practices](https://bestpractices.coreinfrastructure.org/projects/6395/badge)](https://bestpractices.coreinfrastructure.org/projects/6395) - We have walked through the OSSF best practices self certification.  
* [![CodeQl](https://github.com/lmco/hoppr-cop/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/lmco/hoppr-cop/actions/workflows/codeql-analysis.yml) - we have enabled codeql which is high quality SAST scanner targeted at detecting vulnerabilities with low false positive rates. 
* __Protected Branches and Code Reviews__ - All commits to main (following initial release) require a merge request with code review.  
* [__Renovate Bot__](https://docs.renovatebot.com/) - This repository is configured with renovate to ensure we are always up to date with our upstream dependencies. 
* [__SBOM__]() - This project publishes a cyclone-dx compatable SBOM with each release.  It is available under the releases page. 



