package com.vdoo.vision.plugin;

import hudson.FilePath;
import hudson.Launcher;
import hudson.Extension;
import hudson.model.Run;
import hudson.util.Secret;
import hudson.tasks.Builder;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;

import java.net.URL;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

public class ScannerBuilder extends Builder implements SimpleBuildStep {

    private final Secret vdooToken;
    private String failThreshold;
    private String maxHighlightedIssues;
    private String maxHighlightedExposures;
    private String maxHighlightedCVEs;
    private String maxMaliciousFiles;
    private Integer productId;
    private String firmwareLocation;
    private Boolean waitForResults;

    private String baseApi;

    @DataBoundConstructor
    public ScannerBuilder(
            Secret vdooToken,
            String failThreshold,
            String maxHighlightedIssues,
            String maxHighlightedExposures,
            String maxHighlightedCVEs,
            String maxMaliciousFiles,
            Integer productId,
            String firmwareLocation,
            Boolean waitForResults,
            String baseApi
    ) {
        this.vdooToken = vdooToken;
        this.failThreshold = failThreshold;
        this.maxHighlightedIssues = maxHighlightedIssues;
        this.maxHighlightedExposures = maxHighlightedExposures;
        this.maxHighlightedCVEs = maxHighlightedCVEs;
        this.maxMaliciousFiles = maxMaliciousFiles;
        this.waitForResults = waitForResults;
        this.productId = productId;
        this.firmwareLocation = firmwareLocation;
        this.waitForResults = waitForResults;
        this.baseApi = baseApi;
    }

    public Secret getVdooToken() {
        return vdooToken;
    }

    public String getFailThreshold() {
        return failThreshold;
    }

    public String getMaxHighlightedIssues() {
        return maxHighlightedIssues;
    }

    public String getMaxHighlightedExposures() {
        return maxHighlightedExposures;
    }

    public String getMaxHighlightedCVEs() {
        return maxHighlightedCVEs;
    }

    public String getMaxMaliciousFiles() {
        return maxMaliciousFiles;
    }

    public Integer getProductId() {
        return productId;
    }

    public String getFirmwareLocation() {
        return firmwareLocation;
    }

    public String getBaseApi() {
        return baseApi;
    }

    @DataBoundSetter
    public void setBaseApi(String baseApi) {
        this.baseApi = baseApi;
    }

    public Boolean getWaitForResults() {
        return waitForResults;
    }

    @DataBoundSetter
    public void setWaitForResults(Boolean waitForResults) {
        this.waitForResults = waitForResults;
    }

    @DataBoundSetter
    public void setFailThreshold(String failThreshold) {
        this.failThreshold = failThreshold;
    }

    @DataBoundSetter
    public void setMaxHighlightedIssues(String maxHighlightedIssues) {
        this.maxHighlightedIssues = maxHighlightedIssues;
    }

    @DataBoundSetter
    public void setMaxHighlightedExposures(String maxHighlightedExposures) {
        this.maxHighlightedExposures = maxHighlightedExposures;
    }

    @DataBoundSetter
    public void setMaxHighlightedCVEs(String maxHighlightedCVEs) {
        this.maxHighlightedCVEs = maxHighlightedCVEs;
    }

    @DataBoundSetter
    public void setMaliciousFiles(String maxMaliciousFiles) {
        this.maxMaliciousFiles = maxMaliciousFiles;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {
        run.addAction(new ScannerAction(
                this.vdooToken,
                failThreshold,
                maxHighlightedIssues,
                maxHighlightedExposures,
                maxHighlightedCVEs,
                maxMaliciousFiles,
                productId,
                firmwareLocation,
                this.baseApi,
                this.waitForResults,
                listener.getLogger(),
                run
        ));
    }

    @Symbol({ "vdooToken", "failThreshold", "maxHighlightedIssues", "maxHighlightedExposures", "maxHighlightedCVEs",
              "maxMaliciousFiles", "productId", "firmwareLocation", "baseApi" })
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public FormValidation doCheckProductId(@QueryParameter String productId) {
            if ((productId == null) || (productId.equals(""))) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_ProductIdEmpty());
            }

            try {
                Integer.parseInt(productId);
            } catch (NumberFormatException nfe) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_ProductIdNumber());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckFirmwareLocation(@QueryParameter String firmwareLocation) {
            if ((firmwareLocation == null) || (firmwareLocation.equals(""))) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_FirmwareLocationEmpty());
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckVdooToken(@QueryParameter Secret vdooToken) {
            if ((vdooToken == null) || (vdooToken.getPlainText().equals(""))) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_VdooTokenEmpty());
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckBaseApi(@QueryParameter String baseApi) {
            if ((baseApi == null) || (baseApi.equals(""))) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_BaseAPIEmpty());
            }

            try {
                URL baseApiURL= new URL(baseApi);
                if (baseApiURL.getProtocol().equals("https")) {
                    return FormValidation.ok();
                }
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_BaseAPIHttp());

            } catch (Exception e) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_BaseAPIInvalid());
            }
        }

        public FormValidation doCheckMaxHighlightedIssues(@QueryParameter String maxHighlightedIssues) {
            if (maxHighlightedIssues == null || maxHighlightedIssues.equals(""))
                return FormValidation.ok();

            try {
                Integer.parseInt(maxHighlightedIssues);
            } catch (NumberFormatException nfe) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_MaxNumber());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckMaxHighlightedExposures(@QueryParameter String maxHighlightedExposures) {
            if (maxHighlightedExposures == null || maxHighlightedExposures.equals(""))
                return FormValidation.ok();

            try {
                Integer.parseInt(maxHighlightedExposures);
            } catch (NumberFormatException nfe) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_MaxNumber());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckMaxHighlightedCVEs(@QueryParameter String maxHighlightedCVEs) {
            if (maxHighlightedCVEs == null || maxHighlightedCVEs.equals(""))
                return FormValidation.ok();

            try {
                Integer.parseInt(maxHighlightedCVEs);
            } catch (NumberFormatException nfe) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_MaxNumber());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckMaxMaliciousFiles(@QueryParameter String maxMaliciousFiles) {
            if (maxMaliciousFiles == null || maxMaliciousFiles.equals(""))
                return FormValidation.ok();

            try {
                Integer.parseInt(maxMaliciousFiles);
            } catch (NumberFormatException nfe) {
                return FormValidation.error(Messages.ScannerBuilder_DescriptorImpl_MaxNumber());
            }

            return FormValidation.ok();
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.ScannerBuilder_DescriptorImpl_DisplayName();
        }
    }
}
