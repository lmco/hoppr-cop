## [1.1.1](https://gitlab.com/hoppr/hoppr-cop/compare/v1.1.0...v1.1.1) (2023-03-09)


### Bug Fixes

* normalized purl mapping ([7a3d449](https://gitlab.com/hoppr/hoppr-cop/commit/7a3d449920f541df810942f826d872dce244e45c))

## [1.1.0](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.24...v1.1.0) (2023-03-02)


### Features

* adding docker image ([291cca6](https://gitlab.com/hoppr/hoppr-cop/commit/291cca6e734cd371db8c135ac15e250cee8dd9d9))


### Bug Fixes

* updated docker file to include gem install, got gemnasium caching working, added broad catch to cli ([8fbe34a](https://gitlab.com/hoppr/hoppr-cop/commit/8fbe34a791980a509083d93e0bd003eacddeee6c))

## [1.0.24](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.23...v1.0.24) (2023-02-28)


### Bug Fixes

* exposed the ability to specify os distro via the cli or environment variable. This impacts grype's ability to identify vulnerabilities for OS components. ([5f71fc2](https://gitlab.com/hoppr/hoppr-cop/commit/5f71fc2581813bd6638179f56b2bb90d41f954de))

## [1.0.23](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.22...v1.0.23) (2023-02-28)


### Bug Fixes

* the bom generation for trivy was using pydantic and bom-ref was converted to bom_ref. This caused trivy to not report vulnerabilities. This updates the bom generation to just directly go from the dictionary to json. ([c82851a](https://gitlab.com/hoppr/hoppr-cop/commit/c82851a11c7a6ef311b5ad4474edd5fbc1fc8740))

## [1.0.22](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.21...v1.0.22) (2023-02-22)


### Bug Fixes

* Update everything in pyproject.toml to work with upstream dependencies ([fa594c3](https://gitlab.com/hoppr/hoppr-cop/commit/fa594c31b015f56ecc68d132721b605d337726c9))
* Update renovate ([1bec628](https://gitlab.com/hoppr/hoppr-cop/commit/1bec6285fddb69e4e108374482c42d527bf7db8d))
* Update renovate json per linter ([106df54](https://gitlab.com/hoppr/hoppr-cop/commit/106df5416fed3af5638f7b5f7a85830dbd843371))

## [1.0.21](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.20...v1.0.21) (2023-02-09)


### Bug Fixes

* cleaned up pre stage process method and accounting for existing vex ([0b077e5](https://gitlab.com/hoppr/hoppr-cop/commit/0b077e5f7e22e2b594820f58fe476c6585d6ea0b))
* updated plugin to update delivered bom ([5de6f52](https://gitlab.com/hoppr/hoppr-cop/commit/5de6f52422deae7d460b11269f42866d9a6e53f8))

## [1.0.20](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.19...v1.0.20) (2023-01-26)


### Bug Fixes

* adding `poetry lock --no-update` to support renovate MRs. ([9ff7498](https://gitlab.com/hoppr/hoppr-cop/commit/9ff7498e9fb7be643920ac1089366cb8e43267d5))
* update unit test ([0145ba7](https://gitlab.com/hoppr/hoppr-cop/commit/0145ba7170a6c048388a9ced9f57cdeba6f0b7fd))
* updated hoppr version ([020ec43](https://gitlab.com/hoppr/hoppr-cop/commit/020ec4396a64f59b5c912a5b6e19a069a1c87492))

## [1.0.19](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.18...v1.0.19) (2023-01-25)


### Bug Fixes

* **deps:** updating commons version to include gitlab reporting fix ([c6c1c31](https://gitlab.com/hoppr/hoppr-cop/commit/c6c1c31f713509ae85a2aa5ae80a4bddd49ccf29))

## [1.0.18](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.17...v1.0.18) (2023-01-18)


### Bug Fixes

* add integration test job ([c5dea95](https://gitlab.com/hoppr/hoppr-cop/commit/c5dea95f921126a899dba513a594b8cdd15f99af))
* add plugin unit tests ([55d4625](https://gitlab.com/hoppr/hoppr-cop/commit/55d4625d36c29cc2af8e03f733d8800a412298e2))
* **plugin:** added hoppr plugin ([ec3105f](https://gitlab.com/hoppr/hoppr-cop/commit/ec3105f8943e5b499e6db36fc64b47d22036819b))

## [1.0.17](https://gitlab.com/hoppr/hoppr-cop/compare/v1.0.16...v1.0.17) (2022-12-16)


### Bug Fixes

* Bot label for renovate ([3b835f5](https://gitlab.com/hoppr/hoppr-cop/commit/3b835f59e33b267b5070cbb3ccf506d6a5885c41))
* hoppr-security-commons deps ([8feeff6](https://gitlab.com/hoppr/hoppr-cop/commit/8feeff66b3b2622b9de3bb22f5a8ee6150a1e7a1))
* Set renovate config ([fa0de59](https://gitlab.com/hoppr/hoppr-cop/commit/fa0de594f06652c98a4efe238542941bf35c8848))
* updated gitlab namespace ([18968a5](https://gitlab.com/hoppr/hoppr-cop/commit/18968a525cf7559fc8bcf146c9886ebdbc6a2e27))

## [1.0.16](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.15...v1.0.16) (2022-10-19)


### Bug Fixes

* fixed an issue where get_vulnerabilities_by_purl was calling get_vulnerabilities_by_sbom on the underlying scanners ([e5ae0d6](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/e5ae0d600a0b9f8910ff360320eb64143b3b9ab9))

## [1.0.15](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.14...v1.0.15) (2022-10-19)


### Bug Fixes

* remove sbom before regenerating it ([4ed0470](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/4ed0470620db9ae01e5c4b081a0427e67444d951))
* removing references to internal LM resources ([31e112e](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/31e112ebc38139f1b74ae392a29c49acf5f91454))

## [1.0.14](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.13...v1.0.14) (2022-08-29)


### Bug Fixes

* updating gitlab semantic release version ([a1b4685](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/a1b4685907c450502fa826df99b4a87e10f3b147))

## [1.0.13](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.12...v1.0.13) (2022-08-28)


### Bug Fixes

* trying to get release artifacts working ([cfbf1cd](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/cfbf1cd6b50190bac8d096a66a8c985f7c223892))

## [1.0.12](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.11...v1.0.12) (2022-08-28)


### Bug Fixes

* Adding license and sbom to release artifacts ([70c5960](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/70c59603e17baaea63694eee676fdb93fd9f308c))

## [1.0.11](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.10...v1.0.11) (2022-08-27)

## [1.0.10](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.9...v1.0.10) (2022-08-18)

## [1.0.9](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.8...v1.0.9) (2022-08-18)

## [1.0.8](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.7...v1.0.8) (2022-08-18)

## [1.0.7](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.6...v1.0.7) (2022-08-18)


### Bug Fixes

* fixed documentation ([75b12c7](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/75b12c736979fd84c91ecf459dcf4d6f0bf03199))

## [1.0.6](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.5...v1.0.6) (2022-08-18)

## [1.0.5](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.4...v1.0.5) (2022-08-18)

## [1.0.4](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.3...v1.0.4) (2022-08-18)


### Bug Fixes

* added license to the project metadata file ([18fb87f](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/18fb87f073996d3157cb12b8bcaf7c8cd734df91))

## [1.0.3](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.2...v1.0.3) (2022-08-18)

## [1.0.2](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.1...v1.0.2) (2022-08-17)

## [1.0.1](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/compare/v1.0.0...v1.0.1) (2022-08-17)


### Bug Fixes

* changed to use common python module.  Added examples to the documentation. ([b0560f5](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/b0560f5f0300e1c8fc585f1a0bc0e764f48d7806))
* changed to use common python module.  Added examples to the documentation. ([2747d2b](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/2747d2bf1254185c5356f3a67769c5abba00c322))

## 1.0.0 (2022-08-17)


### Features

* added file headers removed extra files, cleaned up docs. ([be06039](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/be060391ac6d22bf0b093fc442550a51f7d20a03))
* use the vex format from grype ([f3d1306](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/f3d13069dfe8f6979d4cff8335ef3f6820faa4cf))


### Bug Fixes

* fixing pipeline issues ([f6b6e51](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/f6b6e51232c8b22a89c7149306a187b1882ab96f))
* fixing semantic release ([abfeefd](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/abfeefd1cff350de63056d973074a537c98837cb))
* linting issues ([585125f](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/585125f1022793e807a32455828483c58f1a7809))
* moved packages around and fixed ci issues ([0e58a3d](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/0e58a3d15d6a39a04be5ba7a2eac8820076ce635))
* updated gemnasium to work properly with the comunity datasource by default, and to update every 24 hours. ([11dea2a](https://gitlab.com/lmco/hoppr/utilities/supply-chain-security/hoppr-cop/commit/11dea2aa3ce28c31f0aa97bead3686071ffafbec))
