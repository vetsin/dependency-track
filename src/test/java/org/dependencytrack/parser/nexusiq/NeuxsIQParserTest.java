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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Component;
import org.json.JSONObject;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class NeuxsIQParserTest { //extends PersistenceCapableTest {
    private JSONObject object;

    @Before
    public void setUp() throws IOException {
        String jsonString = new String(Files.readAllBytes(Paths.get("src/test/resources/unit/nexusiq.jsons/evaluation_response_npm.json")));
        this.object = new JSONObject(jsonString);
    }

    @Test
    public void testParserLoad() {
        var parser = new NexusIQParser();
        var newObject = new JSONObject(object.toString());
        newObject.put("isError", true);
        newObject.put("errorMessage", "unit test error");

        Assert.assertThrows("unit test error", NexusIQParser.EvaluationException.class, () -> {
            new NexusIQParser();
        });
    }

    @Test
    public void testComponentMatch() throws NoSuchMethodException, MalformedPackageURLException, InvocationTargetException, IllegalAccessException {
        var parser = new NexusIQParser();

        var c1 = new Component();
        var purl = new PackageURL("pkg:npm/npm@5.1.0");
        c1.setPurl(purl);

    }
}
