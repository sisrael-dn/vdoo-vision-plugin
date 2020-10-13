package io.jenkins.plugins.sample;

import hudson.model.Run;
import jenkins.model.RunAction2;

public class HelloWorldAction implements RunAction2 {
    private String name;
    private transient Run run;

    public HelloWorldAction(String name){
        this.name = name;
    }

    public String getName(){
        return this.name;
    }

    @Override
    public String getIconFileName()
    {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "Greet";
    }

    @Override
    public String getUrlName() {
        return "greet";
    }

    @Override
    public void onAttached(Run<?, ?> run) {
        this.run = run;
    }

    @Override
    public void onLoad(Run<?, ?> run) {
        this.run = run;
    }

    public Run getRun() {
        return run;
    }
}
