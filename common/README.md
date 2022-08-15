## TODO 
- Currently, the severity shown in reports is based on the first rating in the list.  This should be smarter and select from the best rating method. 
- the vulnerability combiner needs some more work to really combine al fields in an intelligent way. 
- `pkg:npm/minimist@1.2.5` is reporting the following rating for a vulnerability that doesn't make sense. It is a different score than the same vector from another source, and it is showing a  medium severity with a score of 8.1 `medium 8.1	CVSSv31	CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H`
## Development 

The html reports make use of tailwind. If editing them you will want to follow the instructions [here](https://tailwindcss.com/docs/installation) to install tailwind on your machine. 
once installed this is the command to get tailwind to property update the assets/vulnerability.css file when you edit templates. 
`npx tailwindcss -i ./vulnerability.css -o ./assets/vulnerabilities.css --watch
`

## Notes 

cyclonedx 1.3 boms cannot be enhanced with vulnerabilities, because that spec version did not support vulnerabilities. 