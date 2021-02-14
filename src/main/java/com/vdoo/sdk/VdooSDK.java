package com.vdoo.sdk;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class VdooSDK {

    private static final String __Version__ = "0.1.0";
    private static final String SDK_VERSION = __Version__;
    private static final String SDK_NAME = "VdooSDK";

    private static final int MAX_UPLOAD_CONCURRENCY = 5;
    private static final int UPLOAD_RETRIES = 5;

    private String baseUrl;

    private static class AbortException extends IOException {
        public int statusCode;
        public AbortException(int statusCode, String message) {
            super(message);
            this.statusCode = statusCode;
        }

        private static final long serialVersionUID = 1L;
    }

    private JsonNode callUrl(String urlString, String method, String token, byte[] postParams) throws IOException {
        if (!urlString.startsWith("http"))
            urlString = baseUrl + urlString;

        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestProperty("Accept", "application/json");
        connection.setRequestProperty("Content-Type", "application/json");
        connection.setConnectTimeout(5000);
        connection.setRequestMethod(method);
        connection.setDoOutput(true);
        if (token != null)
            connection.setRequestProperty("Authorization", "Token " + token);

        if (postParams != null) {
            int postDataLength = postParams.length;
            connection.setRequestProperty( "Content-Length", Integer.toString(postDataLength));
            DataOutputStream wr = new DataOutputStream(connection.getOutputStream());
            wr.write(postParams);
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
                        connection.getResponseCode(),
                        "Calling url " + urlString + " returned an error status code: " + error_code
                );
            }

            Scanner s = new Scanner(responseStream, "UTF-8").useDelimiter("\\A");
            String result = s.hasNext() ? s.next() : "";

            ObjectMapper mapper = new ObjectMapper();
            String error = "Calling url " + urlString + " returned an error:" + mapper.readTree(result).toString();
            throw new AbortException(connection.getResponseCode(), error);
        }
    }

    private class MultipartUploader {
        RandomAccessFile fileObj;
        String fileName;
        String artifactId;
        String token;
        String imageId;
        int totalParts;
        int maxConcurrency;

        MultipartUploader(RandomAccessFile fileObj, String fileName, String artifactId, String token) {
            this.fileObj = fileObj;
            this.fileName = fileName;
            this.artifactId = artifactId;
            this.token = token;

            imageId = null;
            totalParts = 0;
            maxConcurrency = 0;
        }

        private String upload() throws IOException {
            startUpload();
            maxConcurrency = Math.min(maxConcurrency, MAX_UPLOAD_CONCURRENCY);
            List<PartsUploader> uploaders = new ArrayList<>();
            for (int i = 0; i < maxConcurrency; i++) {
                uploaders.add(new PartsUploader(this, imageId, totalParts, i, maxConcurrency));
            }

            ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(maxConcurrency);
            List<Future<Integer>> futures = new ArrayList<>();
            for (int i = 0; i < maxConcurrency; i++) {
                Future<Integer> future = executor.submit(uploaders.get(i));
                futures.add(future);
            }

            for (int i = 0; i < maxConcurrency; i++) {
                int ret = 0;
                try {
                    ret = futures.get(i).get();
                    if (ret < 0)
                        throw new IOException(String.format("Exception from uploader %d", i));
                } catch (InterruptedException | ExecutionException e) {
                    throw new IOException(String.format("Exception from uploader %d", i));
                }
            }

            finishUpload(imageId);
            return imageId;
        }

        private void startUpload() throws IOException {
            long fileSizeBytes = fileObj.length();

            ObjectMapper mapper = new ObjectMapper();
            ObjectNode uploadParams = mapper.createObjectNode();
            uploadParams.put("artifact_id", this.artifactId);
            uploadParams.put("sdk_version", SDK_VERSION);
            uploadParams.put("sdk_name", SDK_NAME);
            uploadParams.put("file_name", fileName);
            uploadParams.put("file_size_bytes", fileSizeBytes);
            JsonNode uploadDetails = VdooSDK.this.callUrl(
                "/v3/images/upload_request/",
                "POST",
                token,
                uploadParams.toString().getBytes(StandardCharsets.UTF_8));

            imageId = uploadDetails.get("image_uuid").textValue();
            totalParts = uploadDetails.get("total_parts").intValue();
            maxConcurrency = uploadDetails.get("max_concurrency").intValue();
        }

        private void finishUpload(String imageId) throws IOException {
            String finishedUrl = String.format("/v3/images/%s/finished/", imageId);
            callUrl(finishedUrl, "POST", token, null);
        }
    }

    private class PartsUploader implements Callable<Integer> {

        MultipartUploader uploadObj;
        String imageId;
        int totalParts;
        int uploaderId;
        long totalUploaderCount;

        PartsUploader(MultipartUploader uploadObj, String imageId, int totalParts,
         int uploaderId, long totalUploaderCount) {
            this.uploadObj = uploadObj;
            this.imageId = imageId;
            this.totalParts = totalParts;
            this.uploaderId = uploaderId;
            this.totalUploaderCount = totalUploaderCount;
        }

        @Override
        public Integer call() {
            for (int partNumber = 1; partNumber < totalParts + 1; partNumber++) {
                if (((partNumber - 1) % totalUploaderCount) != uploaderId) {
                    continue;
                }

                int retryCount = 0;
                while (retryCount < UPLOAD_RETRIES) {
                    try {
                        startUploadPart(partNumber);
                        break;
                    } catch (Exception e) {
                        retryCount++;
                    }
                }
                if (retryCount == UPLOAD_RETRIES) {
                    return -1;
                }
            }
            return 0;
        }

        private void startUploadPart(int partNumber) throws IOException {
            JsonNode part_details = null;
            String url = String.format("/v3/images/%s/part/%s/", imageId, partNumber);
            try {
                part_details = callUrl(url, "GET", uploadObj.token, null);
                actuallyUploadPart(partNumber, part_details);
            }
            catch (AbortException e) {
                if (e.statusCode == 400 && part_details.get("details").asText().equals("part already uploaded and finished"))
                    return;
                else
                    throw e;
            }
        }

        private void actuallyUploadPart(int partNumber, JsonNode data) throws IOException {
            if (data.get("part_length_bytes").asText().equals("0")) {
                afterUploadPart(partNumber);
                return;
            }

            int offset = data.get("start_offset_bytes").asInt();
            int len = data.get("part_length_bytes").asInt();
            byte[] fileChunk = new byte[len];
            uploadObj.fileObj.seek(offset);
            int ret = uploadObj.fileObj.read(fileChunk, 0, len);

            if (ret != data.get("part_length_bytes").asInt()) {
                String UPLOAD_ERROR = "Error uploading part.%n Problem: %s";
                throw new AbortException(0, String.format(UPLOAD_ERROR, "File read error"));
            }

            callUrl(
                data.get("prepared_request_URL").asText(),
                data.get("prepared_request_method").asText(),
                null,
                fileChunk
            );
            afterUploadPart(partNumber);
        }

        private void afterUploadPart(int partNumber) throws IOException {
            String finishedUrl = String.format("/v3/images/%s/part/%d/finished/", imageId, partNumber);
            callUrl(finishedUrl, "POST", uploadObj.token, null);
        }
    }

    private String uploadFile(String artifactId, String name, String imageFile, String token) throws IOException {
        RandomAccessFile fileObj = new RandomAccessFile(imageFile, "r");
        MultipartUploader uploader = new MultipartUploader(fileObj, name, artifactId, token);
        return uploader.upload();
    }

    private void loopUntilScanDone(String imageUuid, String token, int timeout, boolean verbose)
            throws InterruptedException, IOException {

        final String STATUS_URL = "/v3/images/%s/scan_status/";
        final int SAMPLING_RATE = 5; // Time in seconds between status queries of a report
        LocalDateTime startTime = LocalDateTime.now();
        int currentTry = 1;
        while (startTime.plusSeconds(timeout).isAfter(LocalDateTime.now())) {
            JsonNode res = callUrl(
                String.format(STATUS_URL, imageUuid),
                "GET",
                token,
                null);

            String extractionStatus = res.get("analysis_status").get("current").get("name").asText();
            if (extractionStatus.equals("Success")) {
                if (verbose) {
                    System.out.println("Done");
                }
                return;
            }

            if (extractionStatus.equals("Failure")) {
                res.get("analysis_status").get("current").get("error_code").asText();
                return;
            }

            Thread.sleep(SAMPLING_RATE * 1000);

            if (verbose) {
                String WAITING_FOR_RESULT_SECONDS = "Waiting for results (%d seconds). Current status: %s.";
                System.out.printf((WAITING_FOR_RESULT_SECONDS) + "%n",
                    SAMPLING_RATE * currentTry,
                    extractionStatus);
            }

            currentTry++;
        }
    }

    public String analyzeImage(String baseUrl, String artifactId, String fileName, String filePath, String token)
            throws IOException {
        this.baseUrl = baseUrl;
        String imageUuid = uploadFile(artifactId, fileName, filePath, token);
        return imageUuid;
    }
}
