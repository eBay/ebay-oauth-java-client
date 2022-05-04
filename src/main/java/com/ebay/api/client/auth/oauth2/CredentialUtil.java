/*
 * *
 *  * Copyright (c) 2019 eBay Inc.
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

package com.ebay.api.client.auth.oauth2;

import java.io.InputStream;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.yaml.snakeyaml.Yaml;

import com.ebay.api.client.auth.oauth2.model.Environment;
import org.yaml.snakeyaml.constructor.Constructor;
import org.yaml.snakeyaml.constructor.SafeConstructor;

public class CredentialUtil {
    private static Map<Environment, Credentials> envCredentialsMap = new HashMap<>();
    private static final Logger logger = LoggerFactory.getLogger(CredentialUtil.class);

    public enum CredentialType {
        APP_ID("appid"),
        CERT_ID("certid"),
        DEV_ID("devid"),
        REDIRECT_URI("redirecturi"),;

        private final String configIdentifier;

        CredentialType(String configIdentifier) {
            this.configIdentifier = configIdentifier;
        }

        public static CredentialType lookupBy(String configIdentifier) {
            for (CredentialType credType : values()) {
                if (credType.configIdentifier.equalsIgnoreCase(configIdentifier)) {
                    return credType;
                }
            }
            return null;
        }
    }

    public static class Credentials {
        private final Map<CredentialType, String> credentialTypeLookupMap = new HashMap<>();

        public Credentials(Map<String, String> map) {
            for (Map.Entry<String, String> entry : map.entrySet()) {
                logger.debug(String.format("adding credentials \t%s = %s", entry.getKey(), entry.getValue()));
                CredentialType credentialType = CredentialType.lookupBy(entry.getKey());
                if (null != credentialType) {
                    credentialTypeLookupMap.put(credentialType, entry.getValue());
                }
            }
        }

        public String get(CredentialType credentialType) {
            return credentialTypeLookupMap.get(credentialType);
        }

        @Override
        public String toString() {
            final StringBuilder sb = new StringBuilder();
            sb.append(credentialTypeLookupMap);
            return sb.toString();
        }
    }

    public static void load(InputStream fis) {
        logger.debug("CredentialHelper.load");
        Yaml yaml = new Yaml(new Constructor());
        @SuppressWarnings("unchecked")
		Map<String, ?> values = (Map<String, Map<String, String>>) yaml.loadAs(fis, Map.class);
        logger.debug(yaml.dump(values));
        iterateYaml(values);
    }

    public static void load(String yamlStr) {
        logger.debug("CredentialHelper.load");
        Yaml yaml = new Yaml(new Constructor());
        @SuppressWarnings("unchecked")
		Map<String, ?> values = (Map<String, Map<String, String>>) yaml.loadAs(yamlStr, Map.class);
        iterateYaml(values);
    }

    private static void iterateYaml(Map<String, ?> values) {
        for (String key : values.keySet()) {
            logger.debug("Key attempted: " + key);
            Environment environment = Environment.lookupBy(key);
            if (null == environment) {
                logger.debug("Env key is incorrect: " + key);
                continue;
            }

            Object o = values.get(key);
            if (o instanceof Map) {
                @SuppressWarnings("unchecked")
				Map<String, String> subValues = (Map<String, String>) o;
                Credentials credentials = new Credentials(subValues);
                logger.debug(String.format("adding for %s - %s", environment, credentials.toString()));
                envCredentialsMap.put(environment, credentials);
            }
        }
    }

    public static String dump() {
        return envCredentialsMap.toString();
    }

    public static Credentials getCredentials(Environment environment) {
        return envCredentialsMap.get(environment);
    }
}