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

package com.ebay.api.client.auth.oauth2;

import com.ebay.api.client.auth.oauth2.model.Environment;
import org.yaml.snakeyaml.Yaml;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.HashMap;
import java.util.Map;

public class CredentialLoaderTestUtil {
    public static boolean isAppCredentialsLoaded = false;
    public static boolean isUserCredentialsLoaded = false;

    public static String CRED_USERNAME = null;
    public static String CRED_PASSWORD = null;

    public static void loadAppCredentials() {
        String runtimeParam = System.getProperty("credential_yaml");

        if (runtimeParam != null && !runtimeParam.trim().isEmpty()) {
            System.out.println("Using Runtime Parameter: " + runtimeParam);
            CredentialUtil.load(runtimeParam);
            isAppCredentialsLoaded = true;
        } else {
            //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
            try {
            	CredentialUtil.load(new FileInputStream("src/test/resources/ebay-config.yaml"));
                isAppCredentialsLoaded = true;
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
    }

    @SuppressWarnings("unchecked")
	public static Map<String, Map<String, String>> loadUserCredentials() {
        String runtimeParam = System.getProperty("usercred_yaml");
        Map<String, Map<String, String>> values = new HashMap<>();

        if (runtimeParam != null && !runtimeParam.trim().isEmpty()) {
            System.out.println("Using User Runtime Parameter: " + runtimeParam);
            isUserCredentialsLoaded = true;
            return new Yaml().load(runtimeParam);
        } else {
            //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
            Yaml yaml = new Yaml();
            try {
                values = (Map<String, Map<String, String>>) yaml.loadAs(new FileInputStream("src/test/resources/test-config.yaml"), Map.class);
                isUserCredentialsLoaded = true;
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        return values;
    }

    public static void commonLoadCredentials(Environment environment){
        //TODO: Create the file ebay-config.yaml using the ebay-config-sample.yaml before running these tests
        CredentialLoaderTestUtil.loadAppCredentials();
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }

        // Loading the test user credentials for Sandbox
        Map<String, Map<String, String>> values = CredentialLoaderTestUtil.loadUserCredentials();
        if(!CredentialLoaderTestUtil.isUserCredentialsLoaded){
            System.err.println("\"Please check if test-config.yaml is setup correctly for app credentials");
            return;
        }

        String userCredentialKey = environment.equals(Environment.PRODUCTION) ? "production-user" : "sandbox-user";
        Object valuesObj = values.get(userCredentialKey);
        if (valuesObj instanceof Map) {
            Map<String, String> credValues = (Map<String, String>) valuesObj;
            CRED_USERNAME = credValues.get("username");
            CRED_PASSWORD = credValues.get("password");
        }
    }
}