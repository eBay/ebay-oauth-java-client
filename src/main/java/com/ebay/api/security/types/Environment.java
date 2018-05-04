/*
 * *
 *  * Copyright (c) 2018 eBay Inc.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *  http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *  *
 */

package com.ebay.api.security.types;

public enum Environment {
    PRODUCTION("api.ebay.com", "https://auth.ebay.com/oauth2/authorize", "https://api.ebay.com/identity/v1/oauth2/token"),
    SANDBOX("api.sandbox.ebay.com", "https://auth.sandbox.ebay.com/oauth2/authorize", "https://api.sandbox.ebay.com/identity/v1/oauth2/token");

    private final String configIdentifier;
    private final String webEndpoint;
    private final String apiEndpoint;

    Environment(String configIdentifier, String webEndpoint, String apiEndpoint) {
        this.configIdentifier = configIdentifier;
        this.webEndpoint = webEndpoint;
        this.apiEndpoint = apiEndpoint;
    }

    public String getWebEndpoint() {
        return webEndpoint;
    }

    public String getApiEndpoint() {
        return apiEndpoint;
    }

    public static Environment lookupBy(String configIdentifier) {
        for (Environment env : values()) {
            if (env.configIdentifier.equalsIgnoreCase(configIdentifier)) {
                return env;
            }
        }
        return null;
    }
}
