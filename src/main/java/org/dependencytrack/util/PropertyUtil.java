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
package org.dependencytrack.util;

import alpine.model.ConfigProperty;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.persistence.QueryManager;

import java.net.URI;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;

public class PropertyUtil {

    /**
     * Get a String property, the more common type.
     *
     * @param qm the QueryManager to use
     * @param property the property to get
     * @return The possibly empty value
     */
    public static Optional<String> getProperty(QueryManager qm, ConfigPropertyConstants property) {
        final ConfigProperty theProperty = qm.getConfigProperty(
                property.getGroupName(),
                property.getPropertyName()
        );
        if(theProperty != null) {
            return Optional.ofNullable(theProperty.getPropertyValue());
        }
        return Optional.empty();
    }


    /**
     * Utility function for getting a property, but you get to decide the type!
     * This will throw if the property value cannot be coerced into what you expect
     *
     * @param qm the QueryManager to use
     * @param property the property to get
     * @return The possibly empty value
     * @param <Any> the type we expect it to be
     */
    public static <Any> Optional<Any> getTypedProperty(QueryManager qm, ConfigPropertyConstants property) {
        var prop = getProperty(qm, property);
        Function<String, ?> t = switch (property.getPropertyType()) {
            case NUMBER -> Long::parseLong;
            case STRING -> x -> x;
            case BOOLEAN -> Boolean::parseBoolean;
            case INTEGER -> Long::parseLong;
            case ENCRYPTEDSTRING -> x -> x;
            case TIMESTAMP -> x -> x;
            case URL -> URI::create;
            case UUID -> UUID::fromString;
        };
        return Optional.ofNullable((Any) t.apply(prop.get()));
    }
}
