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
package org.dependencytrack.integrations.sonatype;

import alpine.common.logging.Logger;
import alpine.common.util.UrlUtil;
import alpine.notification.Notification;
import alpine.notification.NotificationLevel;
import alpine.security.crypto.DataEncryption;
import org.apache.http.HttpHeaders;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.dependencytrack.common.HttpClientPool;
import org.dependencytrack.common.ManagedHttpClientFactory;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.notification.NotificationConstants;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.util.PropertyUtil;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

public class NexusIQClient {
    private static final Logger LOGGER = Logger.getLogger(NexusIQClient.class);

    private final URI apiBaseUrl;
    private final String apiToken;

    public NexusIQClient() {
        this(NexusIQClient.confApiBaseUrl(), NexusIQClient.confApiToken());
    }

    public NexusIQClient(URI apiBaseUrl, String apiToken) {
        this.apiBaseUrl = apiBaseUrl;
        this.apiToken = apiToken;
    }

    public Optional<JSONObject> evaluate(String applicationPubId, List<String> purls) {
        final String requestUrl = "%s/api/v2/evaluation/applications/%s" .formatted(apiBaseUrl, applicationPubId);
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

            return Optional.ofNullable(executeRequest(request));
        } catch (Exception ex) {
            handleRequestException(LOGGER, ex);
            return Optional.empty();
        }

    }

    public Optional<JSONObject> getReport(String appId, String reportId) {
        try {
            var builder = new URIBuilder(apiBaseUrl);
            builder.setPathSegments("api", "v2", "evaluation", "applications", appId, "results", reportId);

            var request = new HttpGet(builder.build().toString());
            return Optional.ofNullable(executeRequest(request));
        } catch(Exception ex) {
            handleRequestException(LOGGER, ex);
            return Optional.empty();
        }
    }

    public Optional<JSONObject> getVulnerabilityDetails(String reference) {
       return getVulnerabilityDetails(reference, null) ;
    }

    public Optional<JSONObject> getVulnerabilityDetails(String reference, JSONObject componentIdentifier) {
        try {
            var builder = new URIBuilder(apiBaseUrl);
            builder.setPathSegments("api", "v2", "vulnerabilities", reference);
            if(componentIdentifier != null) {
                builder.addParameter("componentIdentifier", componentIdentifier.toString());
            }
            var request = new HttpGet(builder.build().toString());
            return Optional.ofNullable(executeRequest(request));
        } catch(URISyntaxException | HttpResponseException ex) {
            handleRequestException(LOGGER, ex);
        }
        return null;
    }


    private JSONObject executeRequest(HttpRequestBase request) throws HttpResponseException {
        prepareRequest(request);

        try(CloseableHttpResponse response = HttpClientPool.getClient().execute(request)) {
            int code = response.getStatusLine().getStatusCode();
            if(code >= 200 && code < 300) {
                if(response.getEntity() != null) {
                    String responseString = EntityUtils.toString(response.getEntity());
                    return new JSONObject(responseString);
                }
            } else {
                throw new HttpResponseException(code, EntityUtils.toString(response.getEntity()));
            }
        } catch (IOException ex) {
            handleRequestException(LOGGER, ex);
        }
        return null;
    }

    private void prepareRequest(HttpRequestBase request) {
        request.setHeader(HttpHeaders.USER_AGENT, ManagedHttpClientFactory.getUserAgent());
        request.setHeader(HttpHeaders.AUTHORIZATION, "Basic " + Base64.getEncoder().encodeToString(apiToken.getBytes()));
        request.setHeader(HttpHeaders.ACCEPT, ContentType.APPLICATION_JSON.getMimeType());
    }

    private void handleRequestException(final Logger logger, final Throwable e) {
        logger.error("Request failure", e);
        Notification.dispatch(new Notification()
                .scope(NotificationScope.SYSTEM)
                .group(NotificationGroup.INTEGRATION)
                .title(NotificationConstants.Title.INTEGRATION_ERROR)
                .content("An error occurred while communicating with Nexus IQ. Check log for details. " + e.getMessage())
                .level(NotificationLevel.ERROR)
        );
    }

    public URI getApiBaseUrl() {
        return this.apiBaseUrl;
    }

    public static URI confApiBaseUrl() {
        try (final var qm = new QueryManager()) {
            var prop = PropertyUtil.getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_BASE_URL);
            if(prop.isPresent()) {
                return new URI(UrlUtil.normalize(prop.get()));
            }
        } catch (URISyntaxException e) {
            LOGGER.error("Failed to parse " + ConfigPropertyConstants.SCANNER_NEXUSIQ_BASE_URL, e);
            Notification.dispatch(new Notification()
                    .scope(NotificationScope.SYSTEM)
                    .group(NotificationGroup.CONFIGURATION)
                    .title(NotificationConstants.Title.INTEGRATION_ERROR)
                    .content("Failed to parse the supplied NexusIQ api URL into URI" + e.getMessage())
                    .level(NotificationLevel.ERROR));
        }
        return null;
    }

    public static String confApiToken() {
        try (final var qm = new QueryManager()) {
            var encryptedToken = PropertyUtil.getProperty(qm, ConfigPropertyConstants.SCANNER_NEXUSIQ_USER_TOKEN);
            if (encryptedToken.isPresent()) {
                try {
                    return DataEncryption.decryptAsString((encryptedToken.get()));
                } catch (Exception e) {
                } // om nom nom
            }
            return null;
        }
    }
}
