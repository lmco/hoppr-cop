It is generally quite easy to generate a cycloneDX BOM for your project. The following are tools that should enable you to quickly create an SBOM. 

- [.NET](https://www.nuget.org/packages/CycloneDX/)
- [Conan](https://github.com/CycloneDX/cyclonedx-conan)
- [GO](https://github.com/ozonru/cyclonedx-go)
- [Gradle](https://plugins.gradle.org/plugin/org.cyclonedx.bom)
- [Maven](https://github.com/CycloneDX/cyclonedx-maven-plugin)
- [Python](https://pypi.org/project/cyclonedx-bom/)
- [Ruby Gems](https://rubygems.org/gems/cyclonedx-ruby)
- [NPM](https://www.npmjs.com/package/@cyclonedx/bom)
- [Container](https://github.com/anchore/syft)

`hoppr-cop` consumes `cyclonedx-json` format. If you produce `cyclonedx-xml`, you can convert it to `json` 
with the following commands.

```bash
cat bom.xml | cyclonedx-cli convert --input-format xml --output-format json > bom.json
```

If you have multiple BOMs you need to merge together to get a combined report you can use

```bash
cyclone-cli merge --input-files sbom1.json sbom2.json --output-format json > all_bom.json
```

Full details on the merge options available can be found [Here](https://github.com/CycloneDX/cyclonedx-cli)
