package com.vdoo.vision.plugin;

import java.io.*;
import java.net.URL;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Stream;
import java.net.HttpURLConnection;
import java.util.stream.Collectors;
import java.nio.charset.StandardCharsets;

import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import hudson.model.Run;
import hudson.util.Secret;
import hudson.AbortException;
import jenkins.model.RunAction2;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.vdoo.sdk.VdooSDK;

public class ScannerAction implements RunAction2 {
    public static final String REPORT_DIRECTORY_NAME = "VdooVision";

    // The following properties will be kept inside build.xml for every job (given they are set during ScannerAction)
    private Secret vdooToken;
    private String failThreshold;
    private String maxHighlightedIssues;
    private String maxHighlightedExposures;
    private String maxHighlightedCVEs;
    private String maxMaliciousFiles;
    private String baseApi;
    private String firmwareLocation;
    private Integer artifactId;
    private String firmwareUUID;
    private Boolean waitForResults;
    private String reportLink;
    private String fwName;

    private transient JsonNode analysisResults;
    private transient JsonNode highlightedIssues;
    private transient JsonNode statusJson;
    private transient Map<String, Integer> statusToInt;
    private transient String defaultBaseApi = "https://prod.vdoo.io";

    private transient Run run;

    public ScannerAction(Secret vdooToken, String failThreshold, String maxHighlightedIssues,
                        String maxHighlightedExposures, String maxHighlightedCVEs, String maxMaliciousFiles,
                        Integer artifactId, String firmwareLocation,
                        String baseApi, Boolean waitForResults, PrintStream logger, Run<?, ?> run)
            throws IOException, InterruptedException {

        this.vdooToken = vdooToken;
        if (vdooToken == null || vdooToken.getPlainText().equals("")) {
            throw new AbortException(Messages.ScannerAction_TokenEmptyError());
        }

        this.failThreshold = failThreshold;
        this.maxHighlightedIssues = maxHighlightedIssues;
        this.maxHighlightedExposures = maxHighlightedExposures;
        this.maxHighlightedCVEs = maxHighlightedCVEs;
        this.maxMaliciousFiles = maxMaliciousFiles;
        this.waitForResults = waitForResults;

        this.baseApi = baseApi;
        if (baseApi == null || baseApi.equals("")) {
            this.baseApi = defaultBaseApi;
        }
        if (this.baseApi.endsWith("/")) {
            this.baseApi = this.baseApi.substring(0, this.baseApi.length() - 1);
        }

        this.artifactId = artifactId;
        if (this.artifactId == null) {
            throw new AbortException(Messages.ScannerAction_ProductError());
        }

        this.firmwareLocation = firmwareLocation;
        this.run = run;

        statusToInt = Stream.of(new Object[][]{
            {"None", 20},
            {"Very High",  10},
            {"High",  8},
            {"Medium",  6},
            {"Low",  4},
            {"Very Low",  2},
        }).collect(Collectors.toMap(data -> (String) data[0], data -> (Integer) data[1]));

        File file = new File(this.firmwareLocation);
        if (!file.exists()) {
            throw new AbortException(String.format(
                    Messages.ScannerAction_FirmwareFileMissing(),
                    this.firmwareLocation
            ));
        }

        VdooSDK sdk = new VdooSDK();
        try {
            firmwareUUID = sdk.analyzeImage(
                    this.baseApi,
                    String.valueOf(this.artifactId),
                    file.getName(),
                    this.firmwareLocation,
                    vdooToken.getPlainText());
        } catch (IOException e) {
            throw e;
        }

        logger.println(String.format(
            Messages.ScannerAction_FirmwareUploadSuccess(),
            firmwareUUID
        ));

        if (!waitForResults) {
            logger.println(Messages.ScannerAction_NotWaitingForResults());
            return;
        }

        String status = waitForEndStatus(logger);
        boolean didFail = false;
        String failReason = "";

        if (status.equals("Failure")) {
            failReason = statusJson.get("analysis_status").get("current").get("error_code").textValue();
            didFail = true;
        }
        if (status.equals("timeout")) {
            failReason = status;
            didFail = true;
        }

        if (didFail) {
            String failMessage = String.format(
                    Messages.ScannerAction_FirmwareScanFailure(),
                    failReason,
                    firmwareUUID
            );

            logger.println(failMessage);
            throw new AbortException(failMessage);
        }

        saveReportArtifact(logger);
        saveReportAttributesInJobFile();
        checkThresholds();

        logger.println(Messages.ScannerAction_ScanFinished());
    }

    /*
     * Saving report attributes inside job's build.xml file so it will be available even after jenkins is restarted
     */
    private void saveReportAttributesInJobFile() {
        setReportLink();
        setFwName();
    }

    private boolean isThresholdPassed(String threshold, int actual) {
        if (threshold != null && !threshold.equals("")) {
            int intThreshold = Integer.parseInt(threshold);
            if (actual > intThreshold) {
                return true;
            }
        }
        return false;
    }

    private void checkThresholds() throws AbortException {
        String failMessage = null;

        if (statusToInt.get(getThreatLevel()) >= statusToInt.get(failThreshold)) {
            failMessage = String.format(Messages.ScannerAction_ThreatLevelThresholdPassed(),
                    getThreatLevel(),
                    failThreshold
            );
        }
        else if (isThresholdPassed(maxHighlightedIssues, getHighlightedIssuesCount())) {
            failMessage = String.format(Messages.ScannerAction_HighlightedIssuesThresholdPassed(),
                    getHighlightedIssuesCount(),
                    maxHighlightedIssues);
        }
        else if (isThresholdPassed(maxHighlightedExposures, getHighlightedExposuresCount())) {
            failMessage = String.format(Messages.ScannerAction_HighlightedExposuresThresholdPassed(),
                    getHighlightedExposuresCount(),
                    maxHighlightedExposures);
        }
        else if (isThresholdPassed(maxHighlightedCVEs, getHighlightedCVEsCount())) {
            failMessage = String.format(Messages.ScannerAction_HighlightedCvesThresholdPassed(),
                    getHighlightedCVEsCount(),
                    maxHighlightedCVEs);
        }
        else if (isThresholdPassed(maxMaliciousFiles, getMaliciousFiles())) {
            failMessage = String.format(Messages.ScannerAction_MaliciousFilesThresholdPassed(),
                    getMaliciousFiles(),
                    maxMaliciousFiles);
        }

        if (failMessage != null) {
            throw new AbortException(failMessage);
        }
    }

    private Boolean saveReportArtifact(PrintStream logger) throws IOException {
        File artifactDir = new File(run.getArtifactsDir(), REPORT_DIRECTORY_NAME + run.getQueueId());
        Boolean wasArtifactDirCreated = artifactDir.mkdirs();
        if (wasArtifactDirCreated) {
            ArrayNode analysisResults = dumpReportPart(artifactDir,"analysis_results");
            ArrayNode highlightedIssues = dumpReportPart(artifactDir,"highlighted_issues");
            ArrayNode softwareComponents =  dumpReportPart(artifactDir,"software_components");
            ArrayNode hardwareComponents = dumpReportPart(artifactDir,"hardware_components");
            ArrayNode cves = dumpReportPart(artifactDir,"cves");
            ArrayNode exposures =  dumpReportPart(artifactDir,"exposures");
            ArrayNode maliciousFiles = dumpReportPart(artifactDir,"malicious_files");

            ObjectMapper mapper = new ObjectMapper();
            JsonNode aggregatedReport = mapper.createObjectNode();
            ((ObjectNode) aggregatedReport).set("highlighted_issues", highlightedIssues);
            ((ObjectNode) aggregatedReport).set("software_components", softwareComponents);
            ((ObjectNode) aggregatedReport).set("hardware_components", hardwareComponents);
            ((ObjectNode) aggregatedReport).set("cves", cves);
            ((ObjectNode) aggregatedReport).set("exposures", exposures);
            ((ObjectNode) aggregatedReport).set("malicious_files", maliciousFiles);

            File path = new File(artifactDir, "all_findings.json");
            Writer writer = new OutputStreamWriter(new FileOutputStream(path.toString()), "UTF-8");
            writer.write(aggregatedReport.toPrettyString());
            writer.close();

            this.analysisResults = analysisResults.get(0);
            this.highlightedIssues = highlightedIssues.get(0);
        } else {
            logger.println(Messages.ScannerAction_ArtifactFailed());
        }

        return wasArtifactDirCreated;
    }

    private ArrayNode buildReportPartJson(String report_part_name) throws IOException {
        JsonNode reportPart = callUrl(
                "/v3/images/" + firmwareUUID + "/" + report_part_name,
                "GET",
                null
        );

        if (reportPart.get("next") == null) {
            ArrayNode an = JsonNodeFactory.instance.arrayNode();
            an.add(reportPart);
            return an;
        } else {
            String next_page_url = reportPart.get("next").asText();
            ArrayNode report = (ArrayNode) reportPart.get("results");
            while (!next_page_url.equals("null")) {
                reportPart = callUrl(
                        next_page_url,
                        "GET",
                        null
                );
                report.addAll((ArrayNode) reportPart.get("results"));
                next_page_url = reportPart.get("next").asText();
            }
            return report;
        }
    }

    private ArrayNode dumpReportPart(File artifactDir, String reportPartName) throws IOException {
        File path = new File(artifactDir, reportPartName + ".json");
        Writer writer = new OutputStreamWriter(new FileOutputStream(path.toString()), "UTF-8");
        ArrayNode reportJson = buildReportPartJson(reportPartName);
        writer.write(reportJson.toPrettyString());
        writer.close();
        return reportJson;
    }

    private String waitForEndStatus(PrintStream logger) throws IOException, InterruptedException {
        int maxTries = 60;
        int currentTry = 0;

        while (currentTry < maxTries)
        {
            currentTry += 1;

            statusJson = callUrl(
                "/v3/images/" + firmwareUUID + "/scan_status/",
                "GET",
                null
            );

            String status = statusJson.get("analysis_status").get("current").get("name").textValue();
            if (status.equals("Success") || status.equals("Failure")) {
                return status;
            }

            // Handle the singular minute case - 1 minute, 2 minute**s**:
            if (currentTry == 1) {
                logger.println(String.format(
                        Messages.ScannerAction_ScanWaitMinute(),
                        currentTry,
                        status
                ));
            } else {
                logger.println(String.format(
                        Messages.ScannerAction_ScanWaitMinutes(),
                        currentTry,
                        status
                ));
            }

            Thread.sleep(60 * 1000);
        }

        return "timeout";
    }

    private JsonNode callUrl(String urlString, String method, String postParams) throws IOException {
        if (!urlString.startsWith("http")) {
            urlString = baseApi + urlString;
        }

        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestProperty("accept", "application/json");
        connection.setRequestProperty("Authorization", "Token " + vdooToken.getPlainText());

        HttpURLConnection http = (HttpURLConnection) connection;
        http.setConnectTimeout(5000);
        http.setRequestMethod(method);
        http.setDoOutput(true);

        if (postParams != null) {
            byte[] postData = postParams.getBytes(StandardCharsets.UTF_8);
            int postDataLength = postData.length;
            connection.setRequestProperty( "Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty( "charset", "utf-8");
            connection.setRequestProperty( "Content-Length", Integer.toString( postDataLength ));
            DataOutputStream wr = new DataOutputStream( connection.getOutputStream());
            wr.write(postData);
            wr.close();
        }

        try {
            InputStream responseStream = connection.getInputStream();
            Scanner s = new Scanner(responseStream, "UTF-8").useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "";

            ObjectMapper mapper = new ObjectMapper();
            return mapper.readTree(result);

        } catch (IOException e) {
            InputStream responseStream = connection.getErrorStream();

            if (responseStream == null) {
                String error_code = String.valueOf(connection.getResponseCode());
                throw new AbortException(
                    "Calling url " + urlString + " returned an error status code: " + error_code
                );
            }

            Scanner s = new Scanner(responseStream, "UTF-8").useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "";

            ObjectMapper mapper = new ObjectMapper();
            String error = "Calling url " + urlString + " returned an error:" + mapper.readTree(result).toString();
            throw new AbortException(error);
        }
    }

    @Override
    public String getIconFileName()
    {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "Vdoo Scan Report";
    }

    @Override
    public String getUrlName() {
        return "vdoo-report";
    }

    public String getArtifactName(){
        return analysisResults.get("artifact_name").textValue();
    }

    public String getFwName() {
        if (fwName == null) {
            return analysisResults.get("name").textValue();
        }
        return fwName;
    }

    public void setFwName() {
        if (fwName == null) {
            fwName = analysisResults.get("name").textValue();
        }
    }

    public String getReportLink() {
        if (reportLink == null) {
            reportLink = analysisResults.get("report_link").textValue();
        }
        return reportLink;
    }

    public void setReportLink() {
        if (reportLink == null) {
            reportLink = analysisResults.get("report_link").textValue();
        }
    }

    public Secret getVdooToken() {
        return vdooToken;
    }

    public String getFirmwareUUID() {
        return firmwareUUID;
    }

    public String getThreatLevel() {
        return analysisResults.get("threat_level").textValue();
    }

    public int getHighlightedIssuesCount() {
        return getHighlightedExposuresCount() +
                getHighlightedCVEsCount() +
                getMaliciousFiles();
    }

    public int getHighlightedExposuresCount() {
        return highlightedIssues.get("exposures").size();
    }

    public int getHighlightedCVEsCount() {
        return highlightedIssues.get("cves").size();
    }

    public int getMaliciousFiles() {
        return highlightedIssues.get("malicious_files").size();
    }

    public Boolean getWaitForResults() {
        return waitForResults;
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
