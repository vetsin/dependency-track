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
package org.dependencytrack.parser.nexusiq;

import org.dependencytrack.model.*;
import org.dependencytrack.tasks.scanners.AnalyzerIdentity;
import org.dependencytrack.tasks.scanners.NexusIQAnalysisTask;
import org.json.JSONArray;
import org.json.JSONObject;
import us.springett.cvss.Cvss;

import java.util.List;
import java.util.Objects;
import java.util.function.IntFunction;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class NexusIQParser {

    public NexusIQParser() {
    }

    public JSONObject matchComponent(Component component, JSONArray results) {
        for(int i = 0; i < results.length(); i++) {
            var result = results.getJSONObject(i);
            if(componentMatches(component, result.getJSONObject("component"))) {
                // found it
                return result;
            }
        }
        return null;
    }

    public Vulnerability parseIntoVulnerability(JSONObject vulnDetails) {
        // expects full details
        final Vulnerability vuln = new Vulnerability();
        vuln.setVulnId(vulnDetails.getString("identifier"));
        vuln.setDescription(vulnDetails.getString("description"));
        vuln.setRecommendation(vulnDetails.getString("recommendationMarkdown"));

        var attribution = new FindingAttribution();
        attribution.setAnalyzerIdentity(AnalyzerIdentity.NEXUSIQ_ANALYZER);
        attribution.setReferenceUrl(vulnDetails.optString("vulnerabilityLink"));
        vuln.setFindingAttribution(attribution);

        if(vulnDetails.has("source")) {
            var source = vulnDetails.getJSONObject("source");
            vuln.setSource(source.getString("longName"));
        }

        var vulnIds = vulnDetails.getJSONArray("vulnIds");
        var aliases = stream(vulnIds, vulnIds::getString)
                .map(VulnerabilityAlias::fromString)
                .collect(Collectors.toList());
        vuln.setAliases(aliases);

        vuln.setReferences(vulnDetails.optString("vulnerabilityLink"));
        // technically we could parse the actual source, but we dont seem to track that

        var mainSeverity = vulnDetails.getJSONObject("mainSeverity");
        vuln.setSeverity(Severity.getSeverityByLevel(mainSeverity.getInt("score")));
        if(mainSeverity.optString("source","").contains("cvss") && mainSeverity.has("vector")) {
            vuln.setCvss(Cvss.fromVector(mainSeverity.getString("vector")));
        }
        // will the severity ever be in the form of OWASP...? should check that out.

        var weakness = vulnDetails.optJSONObject("weakness");
        if(weakness != null) {
           // add cwe ids
           var cweIds = weakness.getJSONArray("cweIds") ;
           stream(cweIds, cweIds::getJSONObject)
                   .map(o -> o.getString("id"))
                   .map(Integer::valueOf)
                   .forEach(i -> vuln.addCwe(i));
        }

        if(vulnDetails.has("vulnerableVersionRanges")) {
            var ranges = vulnDetails.getJSONArray("vulnerableVersionRanges");
            vuln.setVulnerableVersions(stream(ranges, ranges::getString).collect(Collectors.joining(",")));
        }

        // We never use the category, explanation, or detection, or link the advisories
        // we also do not include root case information, e.g. pathing

        return vuln;
    }


    /**
     * Small util to deal with streams in a less annoying way
     */
    private <U> Stream<U> stream(JSONArray arr, IntFunction<? extends U> get) {
        return IntStream.range(0, arr.length()).mapToObj(get);
    }


    private boolean componentMatches(Component c1, JSONObject c2) {
        var purl = c1.getPurl();
        if(purl != null) {
            if(purl.toString().equals(c2.optString("packageUrl"))) {
                return true;
            }
            if(NexusIQAnalysisTask.correctPurl(purl).toString().equals(c2.optString("packageUrl"))) {
                return true;
            }
        }
        var id = c2.optJSONObject("componentIdentifier");
        if(id != null) {
            if(Objects.requireNonNull(c1.getSha1()).equals(c2.optString("hash"))) {
                return true;
            }
            // TODO: by format/coords, probably
        }
        return false;
    }

    public List<String> getReferences(JSONObject resultComponent) {
        var securityData = resultComponent.getJSONObject("securityData");
        var securityIssues = securityData.getJSONArray("securityIssues");
        return stream(securityIssues, securityIssues::getJSONObject)
                .map(e -> e.getString("reference"))
                .collect(Collectors.toList());
    }

    public static class EvaluationException extends IllegalArgumentException {
        public EvaluationException(String e) {
            super(e);
        }
    }
}
