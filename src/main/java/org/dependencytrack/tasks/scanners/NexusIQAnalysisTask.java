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
import alpine.event.framework.Event;
import alpine.event.framework.Subscriber;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.event.IndexEvent;
import org.dependencytrack.event.NexusIQAnalysisEvent;
import org.dependencytrack.integrations.sonatype.NexusIQClient;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityAnalysisLevel;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.parser.nexusiq.NexusIQParser;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.NotificationUtil;
import org.dependencytrack.util.PropertyUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;

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
            "a-name", // what IQ says is generic or file
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

    private NexusIQClient client;
    private String orgAppId;
    private boolean aliasSyncEnabled;
    private Integer reportWaitTime;
    private VulnerabilityAnalysisLevel vulnerabilityAnalysisLevel;

    private boolean isEnabled() {
        return super.isEnabled(ConfigPropertyConstants.SCANNER_NEXUSIQ_ENABLED);
    }

    private boolean isConfigured() {
        return this.client != null;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void inform(final Event e) {
        if (e instanceof final NexusIQAnalysisEvent event) {
            if(!isEnabled())
                return;

            try (var qm = new QueryManager()) {
                this.client = new NexusIQClient();

                this.orgAppId = PropertyUtil.getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_ORG_APP_ID).orElse("Dependency-Track");

                this.reportWaitTime = PropertyUtil
                        .<Integer>getTypedProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_REPORT_PERIOD)
                        .orElse(120);

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

        return hasValidPurl && SUPPORTED_PURL_TYPES.stream().anyMatch(Predicate.isEqual(component.getPurl().getType()));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void analyze(final List<Component> components) {

        var uncached = new ArrayList<Component>();
        components.forEach((c) -> {
            if (isCacheCurrent(Vulnerability.Source.NEXUSIQ, this.client.getApiBaseUrl().toString(), c.getPurl().toString())) {
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
        return !isCacheCurrent(Vulnerability.Source.NEXUSIQ, this.client.getApiBaseUrl().toString(), packageUrl.getCoordinates());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void applyAnalysisFromCache(final Component component) {
        applyAnalysisFromCache(Vulnerability.Source.NEXUSIQ, this.client.getApiBaseUrl().toString(),
                        component.getPurl().toString(), component, getAnalyzerIdentity(), vulnerabilityAnalysisLevel);
    }


    /**
     * Not as much 'correct' as make generic and a-name interchangeable
     */
    public static PackageURL correctPurl(PackageURL purl) {
        // easiest way is from string and back...
        String purlStr = purl.toString();
        if(purl.getType().equals(PackageURL.StandardTypes.GENERIC)) {
            purlStr = purlStr.replaceFirst("pkg:generic", "pkg:a-name");
        }
        try {
            return new PackageURL(purlStr);
        } catch(MalformedPackageURLException e) {
            return purl;
        }
    }

    private void analyzeComponents(final List<Component> component) {
        List<String> purls = component.stream().map((c) -> correctPurl(c.getPurl()).toString()).toList();

        try {
            NexusIQClient client = new NexusIQClient();
            var evalResponse = client.evaluate(this.orgAppId, purls);
            if(evalResponse.isEmpty()) {
                //TODO: do something
            }
            var evalResponseJson = evalResponse.get();
            String appId = evalResponseJson.getString("applicationId");
            String resultId = evalResponseJson.getString("resultId");

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
        } catch (Throwable  ex) {
            handleRequestException(LOGGER, ex);
        }
    }

    private Optional<JSONObject> watchReport(String appId, String reportId) throws InterruptedException {
        // try every 5 seconds, up to REPORT_WAIT_TIME
        for(int i = 0; i <= reportWaitTime/5; i++) {
            Optional<JSONObject> response = this.client.getReport(appId, reportId);
            if(response.isPresent()) {
                return response;
            }
            Thread.sleep(5000);
        }
        return Optional.empty();
    }


    private void handle(List<Component> components, final JSONObject object) {
        // object is the FULL report response
        try (QueryManager qm = new QueryManager()) {
            final JSONArray results = object.getJSONArray("results");
            final var iqParser = new NexusIQParser();

            for(Component component : components) {
                var resultComponent = iqParser.matchComponent(component, results);

                List<JSONObject> vulns = iqParser.getReferences(resultComponent).stream()
                        .map(reference -> this.client.getVulnerabilityDetails(reference))
                        .flatMap(Optional::stream)
                        .toList();

                for(JSONObject vulnData : vulns) {
                    Vulnerability vuln = iqParser.parseIntoVulnerability(vulnData);
                    addVulnerabilityToCache(component, vuln);
                    // ill be honst, dont know what this does
                    final Component componentPersisted = qm.getObjectByUuid(Component.class, component.getUuid());
                    if (componentPersisted != null && vuln.getVulnId() != null) {
                        NotificationUtil.analyzeNotificationCriteria(qm, vuln, componentPersisted, vulnerabilityAnalysisLevel);
                        qm.addVulnerability(vuln, componentPersisted, this.getAnalyzerIdentity());
                        LOGGER.debug("NexusIQ vulnerability added : " + vuln.getVulnId() + " to component " + component.getName());
                    }
                    Event.dispatch(new IndexEvent(IndexEvent.Action.COMMIT, Vulnerability.class));
                }

                updateAnalysisCacheStats(qm, Vulnerability.Source.NEXUSIQ, this.client.getApiBaseUrl().toString(), component.getPurl().getCoordinates(), component.getCacheResult());
            }
        }
    }
}
