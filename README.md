# Vdoo Analysis Platform (Vdoo Analysis Plugin)

## Introduction

Vdoo Analysis is a Jenkins plugin that enables Jenkins users to test their images using Vdoo automated security analysis platform as a part of their CI/CD process.

## Configuration

1. To configure your Jenkins project, first add “Vdoo Analysis Plugin” as a build step to your build.
   <img src="./Docs/Screenshots/AddStep.png" alt="" width="381px" height="290px" />

2. *Vision API token* is a token that can be generated from Vdoo Analysis Platform's UI in the User Profile page, under ”Privacy & Security” page. Make sure to store the generated token in a secure manner.

3. *Wait for Analysis Results* determines whether your build pipeline will wait for Vdoo Analysis to complete before moving to the next build step. If this option is not checked, you'll be able to see the report in Vdoo Analysis Platform's web UI or by queries APIs.

4. *Maximal Allowed Threat Level* is the threat level value that if exceeded, Vdoo Analysis Plugin will fail the build. If the value is set to "None", this setting isn't considered when deciding whether to fail the build.
   Note: this setting is only relevant if *Wait for Analysis Results* is checked.

5. *Maximal # of Highlighted issues* is the value that if exceeded, Vdoo Analysis Plugin will fail the build. If the value is left empty, this setting isn't considered when deciding whether to fail the build.
   Note: this setting is only relevant if *Wait for Analysis Results* is checked.

6. *Maximal # of Highlighted Exposures* is the value that if exceeded, Vdoo Analysis Plugin will fail the build. If the value is left empty, this setting isn't considered when deciding whether to fail the build.
   Note: this setting is only relevant if *Wait for Analysis Results* is checked.

7. *Maximal # of Highlighted CVEs* is the value that if exceeded, Vdoo Analysis Plugin will fail the build. If the value is left empty, this setting isn't considered when deciding whether to fail the build.
   Note: this setting is only relevant if *Wait for Analysis Results* is checked.

8. *Maximal # of Malicious Files* is the value that if exceeded, Vdoo Analysis Plugin will fail the build. If the value is left empty, this setting isn't considered when deciding whether to fail the build.
   Note: this setting is only relevant if *Wait for Analysis Results* is checked.

9. *Artifact ID* determines to which of your artifacts the analyzed images are uploaded.  Artifact IDs can be found in Vdoo Analysis Platform's artifact inventory.
   1. In tile view, using the *more options*-->*more info* button  
   <img src="./Docs/Screenshots/MoreOptions.png" alt="" width="326px" height="152" />  <img src="./Docs/Screenshots/MoreInfo.png" width="312px" height="142px" />
   2. In list view, it is displayed in the ID column.
          <img src="./Docs/Screenshots/ListView.png" alt="" width="1042px" height="92" />

10. *Image Location* is the path of the image that will be uploaded to Vdoo Analysis Platform.

11. Under *advanced options* you can find the *Base Vision API URL* field that you should only change if you use a custom Vdoo Analysis Platform installation - any deployment environment whose URL differs from [vision.vdoo.com]().


## Image Analysis

Once configured properly, the plugin will trigger a Vdoo analysis on every pipeline run.
If the *Wait for Analysis Results* option is checked - the plugin will periodically poll Vdoo Analysis Platform for the status, printing it to the console.
When the analysis is completed, *Vdoo Scan Report* is added to the navigation pane of Jenkins.
In the *Vdoo Scan Report* page, you'll have direct access to the report in Vdoo Analysis Platform's UI, and a link to the report in Vdoo Analysis platform.

If *Wait for Analysis Results* isn't checked, the image will be uploaded to Vdoo Analysis platform and the image UUID is printed to the console, to be used in future API calls.

## Contributing

Vdoo welcomes community contribution through pull requests.

## LICENSE

Licensed under Apache-2.0 License, see [LICENSE](LICENSE.md)

	

	
