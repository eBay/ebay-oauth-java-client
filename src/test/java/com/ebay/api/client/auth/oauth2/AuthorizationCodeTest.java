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

import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import com.ebay.api.client.auth.oauth2.model.Environment;
import com.ebay.api.client.auth.oauth2.model.OAuthResponse;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class AuthorizationCodeTest {
    private static String CREDENTIAL_USERNAME = null;
    private static String CREDENTIAL_PASSWORD = null;
    private static final List<String> SCOPE_LIST = Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly"});
    private static final List<String> authorizationScopesList = Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly"});


    //NOTE: Change this env to Environment.PRODUCTION to run this test in PRODUCTION
    private static final Environment EXECUTION_ENV = Environment.SANDBOX;

    @BeforeClass
    public static void testSetup() throws FileNotFoundException {
        // Loading the app credentials
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

        String userCredentialKey = EXECUTION_ENV.equals(Environment.PRODUCTION) ? "production-user" : "sandbox-user";
        Object valuesObj = values.get(userCredentialKey);
        if (null != valuesObj && valuesObj instanceof Map) {
            @SuppressWarnings("unchecked")
			Map<String, String> credentialValues = (Map<String, String>) valuesObj;
            CREDENTIAL_USERNAME = credentialValues.get("username");
            CREDENTIAL_PASSWORD = credentialValues.get("password");
        }
        assertNotNull(CREDENTIAL_USERNAME, "Please check if test-config.yaml is setup correctly");
        assertNotNull(CREDENTIAL_PASSWORD, "Please check if test-config.yaml is setup correctly");
    }

    @Test
    public void testConfigLoadYamlFile() {
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }

        String credentialHelperStr = CredentialUtil.dump();
        System.out.println(credentialHelperStr);
        assertTrue(credentialHelperStr.contains("APP_ID"));
        assertTrue(credentialHelperStr.contains("DEV_ID"));
        assertTrue(credentialHelperStr.contains("CERT_ID"));
        assertTrue(credentialHelperStr.contains("REDIRECT_URI"));
    }

    @Test
    public void testExchangeAuthorizationCode() throws InterruptedException, IOException {
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if(!CredentialLoaderTestUtil.isUserCredentialsLoaded){
            System.err.println("\"Please check if test-config.yaml is setup correctly for user credentials");
            return;
        }

        String authorizationCode = getAuthorizationCode();
        assertNotNull(authorizationCode);

        OAuth2Api auth2Api = new OAuth2Api();
        OAuthResponse oauth2Response = auth2Api.exchangeCodeForAccessToken(EXECUTION_ENV, authorizationCode);
        assertNotNull(oauth2Response);

        assertNotNull(oauth2Response.getRefreshToken().get());
        assertNotNull(oauth2Response.getAccessToken().get());
        assertNull(oauth2Response.getErrorMessage());
        System.out.println("Token Exchange Completed\n" + oauth2Response);
    }

    @Test
    public void testExchangeRefreshForAccessToken() throws InterruptedException, IOException {
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if(!CredentialLoaderTestUtil.isUserCredentialsLoaded){
            System.err.println("\"Please check if test-config.yaml is setup correctly for user credentials");
            return;
        }

        String refreshToken = null;
        String authorizationCode = getAuthorizationCode();
        if(authorizationCode != null){
        	OAuth2Api oauth2Api = new OAuth2Api();
        	OAuthResponse oauth2Response = oauth2Api.exchangeCodeForAccessToken(EXECUTION_ENV, authorizationCode);
        	refreshToken = oauth2Response.getRefreshToken().get().getToken();
        }
        assertNotNull(refreshToken);
  
        OAuth2Api oauth2Api = new OAuth2Api();
        OAuthResponse accessTokenResponse = oauth2Api.getAccessToken(EXECUTION_ENV, refreshToken, SCOPE_LIST);
        assertNotNull(accessTokenResponse);

        assertNotNull(accessTokenResponse.getAccessToken().get());
        assertNull(accessTokenResponse.getErrorMessage());
        assertNull(accessTokenResponse.getRefreshToken().get().getToken());
        System.out.println("Refresh To Access Completed\n" + accessTokenResponse);
    }

    private String getAuthorizationResponseUrl() throws InterruptedException {
        // Optional, if not specified, WebDriver will search your path for chromedriver.
        System.setProperty("webdriver.chrome.driver", "/usr/local/bin/chromedriver");

        WebDriver driver = new ChromeDriver();
        OAuth2Api auth2Api = new OAuth2Api();
        String authorizeUrl = auth2Api.generateUserAuthorizationUrl(EXECUTION_ENV, SCOPE_LIST, Optional.of("current-page"));

        driver.get(authorizeUrl);
        Thread.sleep(5000);

        WebElement userId = (new WebDriverWait(driver, 10))
                .until(ExpectedConditions.visibilityOf(driver.findElement(By.name("userid"))));
        WebElement password = driver.findElement(By.name("pass"));
        
        userId.sendKeys(CREDENTIAL_USERNAME);
        password.sendKeys(CREDENTIAL_PASSWORD);
        driver.findElement(By.name("sgnBt")).submit();

        Thread.sleep(5000);

        String url = null;
        if (driver.getCurrentUrl().contains("code=")) {
            System.out.println("Code Obtained");
            url = driver.getCurrentUrl();
        } else {
            WebElement agreeBtn = (new WebDriverWait(driver, 10))
                    .until(ExpectedConditions.visibilityOf(driver.findElement(By.id("submit"))));

            agreeBtn.submit();
            Thread.sleep(5000);
            url = driver.getCurrentUrl();
        }
        driver.quit();
        return url;
    }
    
    private String getAuthorizationCode() throws InterruptedException { 
    	String url = getAuthorizationResponseUrl();
        int codeIndex = url.indexOf("code=");
        String authorizationCode = null;
        if (codeIndex > 0) {
            Pattern pattern = Pattern.compile("code=(.*?)&");
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
            	authorizationCode = matcher.group(1);
            }
        }
        return authorizationCode;
    }
    
    @Test
    public void testGenerateAuthorizationUrlSandbox() {
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }

        OAuth2Api oauth2Api = new OAuth2Api();
        String authorizationUrl = oauth2Api.generateUserAuthorizationUrl(Environment.SANDBOX, authorizationScopesList, Optional.of("current-page"));
        System.out.println(authorizationUrl);
        assertNotNull(authorizationUrl);
    }

    @Test
    public void testGenerateAuthorizationUrlProduction() {
        if(!CredentialLoaderTestUtil.isAppCredentialsLoaded){
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }

        OAuth2Api oauth2Api = new OAuth2Api();
        String authorizationUrl = oauth2Api.generateUserAuthorizationUrl(Environment.PRODUCTION, authorizationScopesList, Optional.of("current-page"));
        System.out.println(authorizationUrl);
        assertNotNull(authorizationUrl);
    }
}