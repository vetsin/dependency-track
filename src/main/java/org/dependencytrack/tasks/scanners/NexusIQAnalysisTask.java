/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.tasks.scanners;

import alpine.common.logging.Logger;
import alpine.common.util.UrlUtil;
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.model.ConfigProperty;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import com.github.packageurl.PackageURL;
import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.event.NexusIQAnalysisEvent;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nexusiq.NexusIQEvaluationParser;
import org.dependencytrack.persistence.QueryManager;
import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialBackoff;

/**
 * Subscriber task that performs an analysis of component using Snyk vulnerability REST API.
 *
 * @since 4.7.0
 */
public class NexusIQAnalysisTask extends BaseComponentAnalyzerTask implements CacheableScanTask, Subscriber {

    private static final Logger LOGGER = Logger.getLogger(NexusIQAnalysisTask.class);

    // TODO: validate r-cran and yum, c/c++, nuget/pcoff purl types
    private static final Set<String> SUPPORTED_PURL_TYPES = Set.of(
            PackageURL.StandardTypes.CARGO,
            "cocoapods", // Not defined in StandardTypes
            PackageURL.StandardTypes.GENERIC,
            PackageURL.StandardTypes.COMPOSER,
            PackageURL.StandardTypes.GEM,
            PackageURL.StandardTypes.GOLANG,
            PackageURL.StandardTypes.HEX,
            PackageURL.StandardTypes.MAVEN,
            PackageURL.StandardTypes.NPM,
            PackageURL.StandardTypes.NUGET,
            PackageURL.StandardTypes.PYPI
    );

    private String apiBaseUrl;
    //private String apiOrgId;
    private String apiAppPubId;
    private String apiToken;
    private boolean aliasSyncEnabled;
    private int reportWaitTime;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    private String getProperty(QueryManager qm, ConfigPropertyConstants property) {
        final ConfigProperty theProperty = qm.getConfigProperty(
                property.getGroupName(),
                property.getPropertyName()
        );
        if (theProperty == null || theProperty.getPropertyValue() == null) {
            LOGGER.warn(String.format("No property %s provided; skipping", property.getPropertyName()));
            return null;
        }
        return theProperty.getPropertyValue();
    }
    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof final NexusIQAnalysisEvent event) {
            if (!super.isEnabled(ConfigPropertyConstants.SCANNER_NEXUSIQ_ENABLED)) {
                return;
            }
            try (var qm = new QueryManager()) {

                if((this.apiBaseUrl = getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_BASE_URL)) == null) {
                   return;
                }
                if((this.apiAppPubId = getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_ORG_APP_ID)) == null) {
                    return;
                }
                try {
                    String encryptedToken;
                    if((encryptedToken = getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_USER_TOKEN)) == null) {
                        return;
                    }
                    this.apiToken = DataEncryption.decryptAsString(encryptedToken);
                } catch (Exception ex) {
                    LOGGER.error("An error occurred decrypting the Nexus IQ User Token; Skipping", ex);
                    return;
                }

                var wait = getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_REPORT_PERIOD);
                if(wait == null) {
                    this.reportWaitTime = 120;
                } else {
                    this.reportWaitTime = Integer.parseInt(wait);
                }

                this.aliasSyncEnabled = super.isEnabled(ConfigPropertyConstants.SCANNER_NEXUSIQ_ALIAS_SYNC_ENABLED);
            }
            vulnerabilityAnalysisLevel = event.getVulnerabilityAnalysisLevel();
            LOGGER.info("Starting Sonatype Nexus IQ vulnerability analysis task");
            if (!event.getComponents().isEmpty()) {
                analyze(event.getComponents());
            }
            LOGGER.info("Sonatype Nexus IQ vulnerability analysis complete");
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public AnalyzerIdentity getAnalyzerIdentity() {
        return AnalyzerIdentity.NEXUSIQ_ANALYZER;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isCapable(final Component component) {
        final boolean hasValidPurl = component.getPurl() != null
                && component.getPurl().getScheme() != null
                && component.getPurl().getType() != null
                && component.getPurl().getName() != null
                && component.getPurl().getVersion() != null;

        return hasValidPurl && SUPPORTED_PURL_TYPES.stream()
                .anyMatch(purlType -> purlType.equals(component.getPurl().getType()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<Component> components) {

        var uncached = new ArrayList<Component>();
        components.forEach((c) -> {
            if (isCacheCurrent(Vulnerability.Source.NEXUSIQ, apiBaseUrl, c.getPurl().toString())) {
                applyAnalysisFromCache(c);
            } else {
                uncached.add(c);
            }
        });

        analyzeComponents(uncached);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean shouldAnalyze(final PackageURL packageUrl) {
        return getApiBaseUrl()
                .map(baseUrl -> !isCacheCurrent(Vulnerability.Source.NEXUSIQ, apiBaseUrl, packageUrl.getCoordinates()))
                .orElse(false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void applyAnalysisFromCache(final Component component) {
        getApiBaseUrl().ifPresent(baseUrl ->
                applyAnalysisFromCache(Vulnerability.Source.NEXUSIQ, apiBaseUrl,
                        component.getPurl().toString(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel));
    }

    private void analyzeComponents(final List<Component> component) {
        List<String> purls = component.stream().map((c) -> {
            var purl = c.getPurl();
            if(purl.getType() == PackageURL.StandardTypes.GENERIC) {
                return purl.toString().replaceFirst("pkg:generic", "pkg:a-name");
            }
            return purl.toString();
        }).collect(Collectors.toList());


        final String requestUrl = "%s/api/v2/evaluation/applications/%s" .formatted(apiBaseUrl, apiAppPubId);
        try {
            URIBuilder uriBuilder = new URIBuilder(requestUrl);
            var request = new HttpPost(uriBuilder.build().toString());
            prepareRequest(request);

            var carr = new JSONArray();
            for (String purl : purls) {
                var o = new JSONObject();
                o.put("packageUrl", purl);
                carr.put(o);
            }
            var body = new JSONObject();
            body.put("components", carr);

            request.setEntity(new StringEntity(body.toString(), ContentType.APPLICATION_JSON));

            try(CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
                int code = response.getStatusLine().getStatusCode();
                if(response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    JSONObject responseJson = new JSONObject(responseString);
                    if(code >= 200 && code < 300) {
                        String appId = responseJson.getString("applicationId");
                        String resultId = responseJson.getString("resultId");

                        var report = watchReport(appId, resultId);
                        if(report.isPresent()) {
                            var result = report.get();
                            if(!result.getBoolean("isError")) {
                                handle(component, result);
                            } else {
                                var msg = result.getString("errorMessage");
                                LOGGER.error("Error processing report/evaluating components with NexusIQ");
                                Notification.dispatch(new Notification()
                                        .scope(NotificationScope.SYSTEM)
                                        .group(NotificationGroup.ANALYZER)
                                        .title(NotificationConstants.Title.ANALYZER_ERROR)
                                        .content("There was an error evaluting components with NexusIQ: " + msg)
                                        .level(NotificationLevel.ERROR));
                            }
                        } else {
                            LOGGER.error("Timeout getting report from Nexus IQ");
                            Notification.dispatch(new Notification()
                                    .scope(NotificationScope.SYSTEM)
                                    .group(NotificationGroup.ANALYZER)
                                    .title(NotificationConstants.Title.ANALYZER_ERROR)
                                    .content("There was a timeout while waiting for the Nexus IQ component analysis -- consider increasing the timeout property")
                                    .level(NotificationLevel.ERROR));

                        }
                    } else {
                        handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), code, response.getStatusLine().getReasonPhrase());
                    }
                } else {
                    handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), code, response.getStatusLine().getReasonPhrase());
                }
            }
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
    }

    private Optional<JSONObject> watchReport(String appId, String reportId) throws InterruptedException {
        // try every 5 seconds, up to REPORT_WAIT_TIME
        for(int i = 0; i <= reportWaitTime/5; i++) {
            Optional<JSONObject> response = getResults(appId, reportId);
            if(response.isPresent()) {
                return response;
            }
            Thread.sleep(5000);
        }
        return Optional.empty();
    }

    private Optional<JSONObject> getResults(String appId, String reportId) {
        final String requestUrl = "%s/api/v2/evaluation/applications/%s/results/%s" .formatted(apiBaseUrl, appId, reportId);
        try {
            var request = new HttpGet(new URIBuilder(requestUrl).build().toString());
            return executeRequest(request);
        } catch(Exception ex) {
            handleRequestException(LOGGER, ex);
            return Optional.empty();
        }
    }

    private void prepareRequest(HttpRequestBase request) {
        request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
        request.setHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(apiToken.getBytes()));
        request.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    private void handle(List<Component> components, final JSONObject object) {
        // object is the FULL report response
        try (QueryManager qm = new QueryManager()) {
            final JSONArray results = object.getJSONArray("results");
            final var iqParser = new NexusIQEvaluationParser();

            for(Component component : components) {
                var resultComponent = iqParser.matchComponent(component, results);

                iqParser.getReferences(resultComponent).stream().map(reference -> getVulnerabilityDetails(reference))

                var securityData = resultComponent.getJSONObject("securityData");
                var securityIssues = resultComponent.getJSONArray("securityIssues");
                for(var i = 0; i < securityIssues.length(); i++) {
                    var issue = securityIssues.getJSONObject(i);
                    getVulnerabilityDetails(issue.getString("reference"), resultComponent.getJSONObject("component"));
                }
            }

                for (int count = 0; count < data.length(); count++) {
                    Vulnerability synchronizedVulnerability = snykParser.parse(data, qm, purl, count, aliasSyncEnabled);
                    addVulnerabilityToCache(component, synchronizedVulnerability);
                    final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
                    if (componentPersisted != null && synchronizedVulnerability.getVulnId() != null) {
                        NotificationUtil.analyzeNotificationCriteria(qm, synchronizedVulnerability, componentPersisted, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(synchronizedVulnerability, componentPersisted, this.getAnalyzerIdentity());
                        LOGGER.debug("Snyk vulnerability added : " + synchronizedVulnerability.getVulnId() + " to component " + component.getName());
                    }
                    Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                }
            } else {
                //addNoVulnerabilityToCache(component);
            }
            updateAnalysisCacheStats(qm, Vulnerability.Source.SNYK, apiBaseUrl, component.getPurl().getCoordinates(), component.getCacheResult());
        }

    }

    private Optional<Vulnerability> getVulnerabilityDetails(String reference) {
        return getVulnerabilityDetails(reference, null);
    }

    private Optional<Vulnerability> getVulnerabilityDetails(String reference, JSONObject componentIdentifier) {

        if(isCacheCurrent(Vulnerability.Source.NEXUSIQ, apiBaseUrl, reference)) {

        }


        try {
            var builder = new URIBuilder(apiBaseUrl);
            builder.setPathSegments("api", "v2", "vulnerabilities", reference);
            if(componentIdentifier != null) {
                builder.addParameter("componentIdentifier", componentIdentifier.toString());
            }
            var request = new HttpGet(builder.build().toString());
            var vulnData = executeRequest(request);
            var parser = new NexusIQEvaluationParser(null);
            if(vulnData.isEmpty()) {
                return Optional.empty();
            }
            var vuln = parser.parseIntoVulnerability(vulnData.get());
            return Optional.of(vuln);

        } catch(URISyntaxException ex) {
            handleRequestException(LOGGER, ex);
            return Optional.empty();
        }
    }

    private Optional<JSONObject> executeRequest(HttpRequestBase request) {
        prepareRequest(request);

        try(CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            int code = response.getStatusLine().getStatusCode();
            if(code >= 200 && code < 300) {
                if(response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    //
                    return Optional.of(new JSONObject(responseString));
                }
            } else if (code ==  404) {
                LOGGER.error("Request failure -- 404: " + EntityUtils.toString(response.getEntity()));
                return Optional.empty();
            } else {
                handleUnexpectedHttpResponse(LOGGER, request.getURI().toString(), code, response.getStatusLine().getReasonPhrase());
            }
        } catch (Exception ex) {
            handleRequestException(LOGGER, ex);
            return Optional.empty();
        }
    }

    private Optional<String> getApiBaseUrl() {
        if (apiBaseUrl != null) {
            return Optional.of(apiBaseUrl);
        }

        try (final var qm = new QueryManager()) {
            final ConfigProperty property = qm.getConfigProperty(
                    ConfigPropertyConstants.SCANNER_NEXUSIQ_BASE_URL.getGroupName(),
                    ConfigPropertyConstants.SCANNER_NEXUSIQ_BASE_URL.getPropertyName()
            );
            if (property == null) {
                return Optional.empty();
            }

            apiBaseUrl = UrlUtil.normalize(property.getPropertyValue());
            return Optional.of(apiBaseUrl);
        }
    }

}
