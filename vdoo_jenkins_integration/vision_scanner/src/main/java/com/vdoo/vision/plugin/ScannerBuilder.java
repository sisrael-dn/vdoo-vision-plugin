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
import java.io.File;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;


public class ScannerBuilder extends Builder implements SimpleBuildStep {

    private final Secret vdooToken;
    private final String failThreshold;
    private Integer productId;
    private String firmwareLocation;

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

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {

        run.addAction(new ScannerAction(this.vdooToken, failThreshold, productId, firmwareLocation, this.baseApi, listener.getLogger(), run));
    }


    @Symbol({ "vdooToken", "failThreshold", "productId", "firmwareLocation", "baseApi" })
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {
        public FormValidation doCheckProductId(@QueryParameter String productId) {
            if ((productId == null) || (productId.equals(""))) {
                return FormValidation.error("Product ID can't be empty or null.");
            }

            try {
                Integer.parseInt(productId);
            } catch (NumberFormatException nfe) {
                return FormValidation.error("Product Id must be a number.");
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckFirmwareLocation(@QueryParameter String firmwareLocation) {
            if ((firmwareLocation == null) || (firmwareLocation.equals(""))) {
                return FormValidation.error("Firmware location can't be empty or null.");
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
