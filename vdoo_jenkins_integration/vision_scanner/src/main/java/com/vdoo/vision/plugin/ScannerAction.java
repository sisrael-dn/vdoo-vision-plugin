package com.vdoo.vision.plugin;

import com.amazonaws.regions.Regions;
import com.amazonaws.regions.Region;
import com.amazonaws.SdkClientException;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.AmazonServiceException;
import com.amazonaws.services.s3.transfer.Upload;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.services.s3.model.ObjectMetadata;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.transfer.TransferManager;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.s3.transfer.TransferManagerBuilder;


import java.io.*;
import java.net.URI;
import java.net.URL;
import java.util.Map;
import java.util.Scanner;
import java.util.stream.Stream;
import java.time.LocalDateTime;
import java.nio.charset.Charset;
import java.net.HttpURLConnection;
import java.util.stream.Collectors;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;

import hudson.model.Run;
import sun.misc.IOUtils;
import hudson.util.Secret;
import hudson.model.Result;
import hudson.AbortException;
import jenkins.model.RunAction2;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.org.apache.xpath.internal.operations.Bool;


public class ScannerAction implements RunAction2 {
    public static final String REPORT_DIRECTORY_NAME = "VDOOVision";
    private Secret vdooToken;
    private String failThreshold;
    private String baseApi;
    private String firmwareLocation;
    private Integer productId;
    private String firmwareUUID;
    private Boolean waitForResults;

    private transient JsonNode reportJson;
    private transient JsonNode statusJson;
    private Map<String, Integer> statusToInt;
    private transient String sdkName = "jenkins_plugin";
    private transient String sdkVersion = "0.2";
    private transient String defaultBaseApi = "https://prod.vdoo.io/";

    private transient Run run;

    public ScannerAction(Secret vdooToken, String failThreshold, Integer productId, String firmwareLocation, String baseApi, Boolean waitForResults, PrintStream logger, Run<?, ?> run) throws IOException, InterruptedException {
        System.out.println();
        this.vdooToken = vdooToken;
        if (vdooToken == null || vdooToken.getPlainText().equals("")) {
            throw new AbortException(Messages.ScannerAction_TokenEmptyError());
        }

        this.failThreshold = failThreshold;
        this.waitForResults = waitForResults;

        this.baseApi = baseApi;
        if (baseApi == null || baseApi.equals("")) {
            this.baseApi = defaultBaseApi;
        }

        this.productId = productId;
        if (productId == null) {
            throw new AbortException(Messages.ScannerAction_ProductError());
        }

        this.firmwareLocation = firmwareLocation;
        this.run = run;

        statusToInt = Stream.of(new Object[][]{
            {"None", 20},
            { "Very High",  10},
            { "High",  8},
            { "Medium",  6},
            { "Low",  4},
            { "Very Low",  2},
        }).collect(Collectors.toMap(data -> (String) data[0], data -> (Integer) data[1]));

        String uploadParams = "product_id=" + this.productId + "&sdk_version=" + sdkVersion + "&sdk_name=" + sdkName;
        JsonNode uploadDetails = callUrl(
                "v1/cicd/upload_request/",
                "POST",
                uploadParams
        );

        this.firmwareUUID = uploadDetails.get("firmware_id").textValue();
        File file = new File(this.firmwareLocation);
        if (!file.exists()) {
            throw new AbortException(String.format(
                Messages.ScannerAction_FirmwareFileMissing(),
                this.firmwareLocation
            ));
        }

        uploadFileAWS(uploadDetails, file);

        logger.println(String.format(
            Messages.ScannerAction_FirmwareUploadSuccess(),
            this.firmwareUUID
        ));

        if (!this.waitForResults) {
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
                    this.firmwareUUID
            );

            logger.println(failMessage);
            throw new AbortException(failMessage);
        }

        this.reportJson = callUrl(
            "v1/cicd/" + this.firmwareUUID + "/report_results/",
            "GET",
            null
        );

        this.saveReportArtifact(logger);

        if (statusToInt.get(this.getThreatLevel()) >= statusToInt.get(this.failThreshold))
        {
            String failMessage = String.format(
                    Messages.ScannerAction_ThreatLevelThresholdPassed(),
                    this.getThreatLevel(),
                    this.failThreshold
            );
            throw new AbortException(failMessage);
        }

        logger.println(Messages.ScannerAction_ScanFinished());
    }

    private void uploadFileAWS(JsonNode uploadDetails, File file) throws FileNotFoundException, InterruptedException {
        String awsRegion = uploadDetails.get("region").textValue();
        awsRegion = awsRegion.replace('-', '_');
        Regions clientRegion = Regions.valueOf(awsRegion.toUpperCase());

        String bucketName = uploadDetails.get("bucket").textValue();
        String keyName = uploadDetails.get("key").textValue();

        try {
            BasicSessionCredentials creds = new BasicSessionCredentials(
                    uploadDetails.get("access_key_id").textValue(),
                    uploadDetails.get("secret_access_key").textValue(),
                    uploadDetails.get("session_token").textValue()
            );

            AmazonS3 s3Client = AmazonS3ClientBuilder.standard()
                    .withRegion(clientRegion)
                    .withCredentials(new AWSStaticCredentialsProvider(creds))
                    .build();

            TransferManager tm = TransferManagerBuilder.standard()
                    .withS3Client(s3Client)
                    .build();

            ObjectMetadata metadata = new ObjectMetadata();
            metadata.setContentType("plain/text");
            metadata.addUserMetadata("name", file.getName());
            metadata.addUserMetadata("size", "" + file.length());  // file.length returns type "long" without a
                                                                   // toString method. Wat :)

            // TransferManager processes all transfers asynchronously,
            // so this call returns immediately.
            Upload upload = tm.upload(bucketName, keyName, new FileInputStream(file), metadata);

            // Optionally, wait for the upload to finish before continuing.
            upload.waitForCompletion();
        } catch (AmazonServiceException e) {
            // The call was transmitted successfully, but Amazon S3 couldn't process
            // it, so it returned an error response.
            e.printStackTrace();
        } catch (SdkClientException e) {
            // Amazon S3 couldn't be contacted for a response, or the client
            // couldn't parse the response from Amazon S3.
            e.printStackTrace();
        }

        // Sleep one minute to allow the firmware to get taken from the queue:
        Thread.sleep(60 * 1000);
    }

    private Boolean saveReportArtifact(PrintStream logger) throws IOException {
        File artifactDir = new File(run.getArtifactsDir(), REPORT_DIRECTORY_NAME + run.getQueueId());

        Boolean wasArtifactDirCreated = artifactDir.mkdirs();

        if (wasArtifactDirCreated) {
            JsonNode statusJson = this.callUrl(
                    "v1/cicd/" + this.firmwareUUID + "/scan_status/",
                    "GET",
                    null
            );

            Integer reportId = this.statusJson.get("analysis_status").get("report_id").intValue();

            JsonNode fullReportJson = this.callUrl(
                    "v1/firmware/" + reportId + "/",
                    "GET",
                    null
            );

            File path = new File(artifactDir, "vdoo_vision_report_" + reportId + ".json");
            Writer writer = new OutputStreamWriter(new FileOutputStream(path.toString()), "UTF-8");

            try {
                writer.write(fullReportJson.toPrettyString());
                writer.close();
            } catch ( IOException e) {
                writer.close();
            }

        } else {
            logger.println(Messages.ScannerAction_ArtifactFailed());
        }

        return wasArtifactDirCreated;
    }

    private String waitForEndStatus(PrintStream logger) throws IOException, InterruptedException {
        int maxTries = 60;
        int currentTry = 0;

        while (currentTry < maxTries)
        {
            currentTry += 1;

            statusJson = callUrl(
                "v1/cicd/" + this.firmwareUUID + "/scan_status/",
                "GET",
                null
            );

            String status = statusJson.get("analysis_status").get("current").get("name").textValue();
            if (status.equals("Success") || status.equals("Failure")) {
                return status;
            }

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
        urlString = this.baseApi + urlString;

        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();

        connection.setRequestProperty("accept", "application/json");
        connection.setRequestProperty("Authorization", "Token " + this.vdooToken.getPlainText());

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
            Scanner s = new Scanner(responseStream).useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "";
            System.out.println(result);

            ObjectMapper mapper = new ObjectMapper();
            return mapper.readTree(result);
        } catch (IOException e) {
            InputStream responseStream = connection.getErrorStream();
            Scanner s = new Scanner(responseStream).useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "";
            System.out.println(result);

            ObjectMapper mapper = new ObjectMapper();
            return mapper.readTree(result);
        }
    }


    @Override
    public String getIconFileName()
    {
        return "document.png";
    }

    @Override
    public String getDisplayName() {
        return "VDOO Scan Report";
    }

    @Override
    public String getUrlName() {
        return "vdoo-report";
    }

    public Secret getVdooToken() {
        return this.vdooToken;
    }

    public String getFirmwareUUID() {
        return this.firmwareUUID;
    }

    public String getProductName(){
        return this.reportJson.get("product_name").textValue();
    }

    public String getFwName(){
        return this.reportJson.get("name").textValue();
    }

    public String getReportLink(){
        return this.reportJson.get("report_link").textValue();
    }

    public String getCveCount(){
        return Integer.toString(this.reportJson.get("total_cves").intValue());
    }

    public String getSwCount(){
        return Integer.toString(this.reportJson.get("sw_components_count").intValue());
    }

    public String getUnresolvedCount(){
        return Integer.toString(this.reportJson.get("unresolved_exposures_count").intValue());
    }

    public String getThreatLevel(){
        return this.reportJson.get("threat_level").textValue();
    }

    public Boolean getWaitForResults(){
        return this.waitForResults;
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
