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

package com.ebay.api.security;

import com.ebay.api.security.impl.EbayAuthApi;
import com.ebay.api.security.openid.jwt.EbayIdTokenValidator;
import com.ebay.api.security.types.Environment;
import com.ebay.api.security.types.OAuthResponse;
import com.ebay.api.security.v1.IEbayAuthApi;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ebay.api.security.CredentialLoaderTestUtil.CRED_PASSWORD;
import static com.ebay.api.security.CredentialLoaderTestUtil.CRED_USERNAME;
import static org.junit.Assert.*;

public class AuthorizationCodeTest {
    private static final List<String> SCOPES_LIST = Arrays.asList(new String[]{"https://api.ebay.com/oauth/api_scope", "https://api.ebay.com/oauth/api_scope/sell.marketing.readonly"});

    //NOTE: Change this env to Environment.PRODUCTION to run this test in PRODUCTION
    private static final Environment EXECUTION_ENV = Environment.SANDBOX;

    @BeforeClass
    public static void testSetup() {
        CredentialLoaderTestUtil.commonLoadCredentials(EXECUTION_ENV);
        assertNotNull(CRED_USERNAME, "Please check if test-config.yaml is setup correctly");
        assertNotNull(CRED_PASSWORD, "Please check if test-config.yaml is setup correctly");
    }

    @Test
    public void testEbayConfigLoadYamlFile() {
        if (!CredentialLoaderTestUtil.isAppCredentialsLoaded) {
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }

        String credentialHelperStr = CredentialHelper.dump();
        System.out.println(credentialHelperStr);
        assertTrue(credentialHelperStr.contains("APP_ID"));
        assertTrue(credentialHelperStr.contains("DEV_ID"));
        assertTrue(credentialHelperStr.contains("CERT_ID"));
        assertTrue(credentialHelperStr.contains("REDIRECT_URI"));
    }

    @Test
    public void exchangeAuthzCode() throws InterruptedException, IOException {
        if (!CredentialLoaderTestUtil.isAppCredentialsLoaded) {
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if (!CredentialLoaderTestUtil.isUserCredentialsLoaded) {
            System.err.println("\"Please check if test-config.yaml is setup correctly for app credentials");
            return;
        }

        String url = getAuthorizationResponseUrl();
        int codeIndex = url.indexOf("code=");
        String code = null;
        if (codeIndex > 0) {
            Pattern pattern = Pattern.compile("code=(.*?)&");
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
                code = matcher.group(1);
            }
        }

        assertNotNull(code);

        IEbayAuthApi authApi = new EbayAuthApi();
        OAuthResponse authResponse = authApi.exchangeCode(EXECUTION_ENV, code);
        assertNotNull(authResponse);

        assertNotNull(authResponse.getRefreshToken().get());
        assertNotNull(authResponse.getAccessToken().get());
        assertNull(authResponse.getErrorMessage());
        System.out.println("Token Exchange Completed\n" + authResponse);

        performRefreshToAccessTest(authResponse.getRefreshToken().get().getToken());
    }

    private void performRefreshToAccessTest(String refreshToken) throws IOException {
        IEbayAuthApi authApi = new EbayAuthApi();
        OAuthResponse accessTokenResponse = authApi.getAccessToken(EXECUTION_ENV, refreshToken, SCOPES_LIST);
        assertNotNull(accessTokenResponse);

        assertNotNull(accessTokenResponse.getAccessToken().get());
        assertNull(accessTokenResponse.getErrorMessage());
        assertNull(accessTokenResponse.getRefreshToken().get().getToken());
        System.out.println("Refresh To Access Completed\n" + accessTokenResponse);
    }

    public String getAuthorizationResponseUrl() throws InterruptedException {
        // Optional, if not specified, WebDriver will search your path for chromedriver.
        System.setProperty("webdriver.chrome.driver", "/usr/local/bin/chromedriver");

        WebDriver driver = new ChromeDriver();
        IEbayAuthApi authApi = new EbayAuthApi();
        String authorizeUrl = authApi.generateUserAuthorizeUrl(EXECUTION_ENV, SCOPES_LIST, Optional.of("current-page"));

        driver.get(authorizeUrl);
        Thread.sleep(5000);

        WebElement userId = (new WebDriverWait(driver, 10))
                .until(ExpectedConditions.visibilityOf(driver.findElement(By.cssSelector("input[type='text']"))));

        WebElement password = driver.findElement(By.cssSelector("input[type='password']"));
        userId.sendKeys(CRED_USERNAME);
        password.sendKeys(CRED_PASSWORD);
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
}