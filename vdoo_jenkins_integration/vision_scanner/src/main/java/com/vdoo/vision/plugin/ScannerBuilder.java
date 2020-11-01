package com.vdoo.vision.plugin;

import hudson.FilePath;
import hudson.Launcher;
import hudson.Extension;
import hudson.model.Job;
import hudson.model.Run;
import hudson.util.Secret;
import hudson.model.Result;
import hudson.tasks.Builder;
import hudson.model.TaskListener;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.tasks.BuildStepDescriptor;

import com.vdoo.vision.plugin.ScannerAction;
import javax.servlet.ServletException;
import java.net.URL;
import java.io.File;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.jenkinsci.plugins.workflow.steps.AbstractStepDescriptorImpl;
import org.jenkinsci.plugins.workflow.steps.StepExecution;


public class ScannerBuilder extends Builder implements SimpleBuildStep {

    private final Secret vdooToken;
    private final String failThreshold;
    private Integer productId;
    private String firmwareLocation;
    private Boolean waitForResults;

    private String baseApi;

    @DataBoundConstructor
    public ScannerBuilder(Secret vdooToken, String failThreshold, Integer productId, String firmwareLocation) {
        this.vdooToken = vdooToken;
        this.failThreshold = failThreshold;
        this.productId = productId;
        this.firmwareLocation = firmwareLocation;
    }

    public Secret getVdooToken() {
        return vdooToken;
    }

    public String getFailThreshold() {
        return failThreshold;
    }

    public Integer getProductId() {
        return productId;
    }

    public String getFirmwareLocation() {
        return firmwareLocation;
    }

    @DataBoundSetter
    public void setBaseApi(String baseApi) {
        this.baseApi = baseApi;
    }

    @DataBoundSetter
    public void setWaitForResults(Boolean waitForResults) {
        this.waitForResults = waitForResults;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {
        run.addAction(new ScannerAction(
                this.vdooToken,
                failThreshold,
                productId,
                firmwareLocation,
                this.baseApi,
                this.waitForResults,
                listener.getLogger(),
                run
        ));
    }


    @Symbol({ "vdooToken", "failThreshold", "productId", "firmwareLocation", "baseApi" })
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
