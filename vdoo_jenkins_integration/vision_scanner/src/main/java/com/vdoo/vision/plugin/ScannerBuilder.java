package com.vdoo.vision.plugin;

import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.Run;
import hudson.model.Result;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import com.vdoo.vision.plugin.ScannerAction;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import hudson.util.Secret;

import javax.servlet.ServletException;
import java.io.IOException;
import jenkins.tasks.SimpleBuildStep;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundSetter;

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

    @Symbol("greet")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        public FormValidation doCheckName(@QueryParameter String value, @QueryParameter boolean useFrench)
                throws IOException, ServletException {

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
