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

import com.ebay.api.client.auth.oauth2.CredentialLoaderTestUtil;
import com.ebay.api.client.auth.oauth2.CredentialUtil;
import com.ebay.api.client.auth.oauth2.OAuth2Api;
import com.ebay.api.client.auth.oauth2.model.Environment;
import com.ebay.api.security.types.EbayIdToken;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.WebElement;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import java.util.Collections;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ebay.api.client.auth.oauth2.CredentialLoaderTestUtil.CRED_PASSWORD;
import static com.ebay.api.client.auth.oauth2.CredentialLoaderTestUtil.CRED_USERNAME;
import static com.ebay.api.security.openid.jwt.EbayIdTokenValidator.JWTExtractException;
import static com.ebay.api.security.openid.jwt.EbayIdTokenValidator.validate;
import static org.junit.Assert.*;

public class EbayIdTokenValidatorTest {
    //NOTE: Change this env to Environment.PRODUCTION to run this test in PRODUCTION
    private static final Environment EXECUTION_ENV = Environment.PRODUCTION;

    @BeforeClass
    public static void testSetup() {
        CredentialLoaderTestUtil.commonLoadCredentials(EXECUTION_ENV);
        assertNotNull(CRED_USERNAME, "Please check if test-config.yaml is setup correctly");
        assertNotNull(CRED_PASSWORD, "Please check if test-config.yaml is setup correctly");
    }

    @Test
    public void generateIdTokenAndVerify() throws InterruptedException {
        if (!CredentialLoaderTestUtil.isAppCredentialsLoaded) {
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if (!CredentialLoaderTestUtil.isUserCredentialsLoaded) {
            System.err.println("\"Please check if test-config.yaml is setup correctly for app credentials");
            return;
        }

        String nonce = UUID.randomUUID().toString();
        String url = getIdTokenResponseUrl(nonce);
        int idTokenIndex = url.indexOf("id_token=");
        String idToken = null;
        if (idTokenIndex > 0) {
            Pattern pattern = Pattern.compile("id_token=(.*?)$");
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
                idToken = matcher.group(1);
            }
        }

        assertNotNull(idToken);
        String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
        EbayIdToken ebayIdToken = validate(idToken, Collections.singletonList(appId));
        assertNotNull(ebayIdToken);
        assertEquals("oauth.ebay.com", ebayIdToken.getIssuer());
        assertEquals(nonce, ebayIdToken.getNonce());
        assertEquals(appId, ebayIdToken.getAudience());
        assertTrue(ebayIdToken.getIssuedAt() < (new Date().getTime() / 1000));
        assertTrue(ebayIdToken.getExpiresAt() > (new Date().getTime() / 1000));
        assertTrue(ebayIdToken.toString().contains(ebayIdToken.getPreferedUserName()));
        assertNotNull(ebayIdToken.getSubject());
    }

    public String getIdTokenResponseUrl(String nonce) throws InterruptedException {
        // Optional, if not specified, WebDriver will search your path for chromedriver.
        System.setProperty("webdriver.chrome.driver", "/usr/local/bin/chromedriver");

        WebDriver driver = new ChromeDriver();
        OAuth2Api authApi = new OAuth2Api();
        String idTokenUrl = authApi.generateIdTokenUrl(EXECUTION_ENV, Optional.of("current-page"), nonce);

        driver.get(idTokenUrl);
        Thread.sleep(5000);

        WebElement userId = (new WebDriverWait(driver, 10))
                .until(ExpectedConditions.visibilityOf(driver.findElement(By.cssSelector("input[type='text']:not([name='userid_otp']):not([name='otp'])"))));

        WebElement password = driver.findElement(By.cssSelector("input[type='password']"));
        userId.sendKeys(CRED_USERNAME);
        password.sendKeys(CRED_PASSWORD);
        WebElement sgnBt = null;
        try {
            sgnBt = driver.findElement(By.name("sgnBt"));
        } catch (NoSuchElementException e) {
            // ignore exception
        }
        if (sgnBt == null) {
            sgnBt = driver.findElement(By.id("sgnBt"));
        }

        sgnBt.submit();
        Thread.sleep(5000);

        String url = null;
        if (driver.getCurrentUrl().contains("id_token=")) {
            System.out.println("Id Token Obtained");
            url = driver.getCurrentUrl();
        } else {
            WebElement agreeBtn = (new WebDriverWait(driver, 10))
                    .until(ExpectedConditions.visibilityOf(driver.findElement(By.id("submit"))));

            agreeBtn.submit();
            Thread.sleep(5000);
            url = driver.getCurrentUrl();
        }
        driver.quit();
        System.out.println(url);
        return url;
    }

    @Test
    public void idTokenFailureWithIncorrectAud() throws InterruptedException {
        if (!CredentialLoaderTestUtil.isAppCredentialsLoaded) {
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if (!CredentialLoaderTestUtil.isUserCredentialsLoaded) {
            System.err.println("\"Please check if test-config.yaml is setup correctly for app credentials");
            return;
        }

        String nonce = UUID.randomUUID().toString();
        String url = getIdTokenResponseUrl(nonce);
        int idTokenIndex = url.indexOf("id_token=");
        String idToken = null;
        if (idTokenIndex > 0) {
            Pattern pattern = Pattern.compile("id_token=(.*?)$");
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
                idToken = matcher.group(1);
            }
        }

        assertNotNull(idToken);
        try {
            EbayIdToken ebayIdToken = validate(idToken, Collections.singletonList("test"));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertTrue(e.getMessage().contains("IDToken generated for Client: "));
        }
    }

    @Test
    public void parseIDTokenSignatureError() throws InterruptedException {
        if (!CredentialLoaderTestUtil.isAppCredentialsLoaded) {
            System.err.println("\"Please check if ebay-config.yaml is setup correctly for app credentials");
            return;
        }
        if (!CredentialLoaderTestUtil.isUserCredentialsLoaded) {
            System.err.println("\"Please check if test-config.yaml is setup correctly for app credentials");
            return;
        }

        String nonce = UUID.randomUUID().toString();
        String url = getIdTokenResponseUrl(nonce);
        int idTokenIndex = url.indexOf("id_token=");
        String idToken = null;
        if (idTokenIndex > 0) {
            Pattern pattern = Pattern.compile("id_token=(.*?)$");
            Matcher matcher = pattern.matcher(url);
            if (matcher.find()) {
                idToken = matcher.group(1);
            }
        }

        assertNotNull(idToken);
        System.out.println(idToken);
        String[] split = idToken.split("\\.");
        String invalidIdToken = split[0] + "." + split[1] + "." + "invalidsignature";
        try {
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(invalidIdToken, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("Exception verifying signature: Signature length not correct: got 12 but was expecting 256", e.getMessage());
        }
    }

    @Test
    public void parseIDTokenErrorsEmpty() {
        try {
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate("", Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("ID token is null or empty", e.getMessage());
        }
    }

    @Test
    public void parseIDTokenErrorsMultipleParts() {
        try {
            String multiParts = "test.test.test.test";
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(multiParts, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("invalid id token not all parts present", e.getMessage());
        }
    }

    @Test
    public void parseIDTokenErrorsOnePartEmpty() {
        try {
            String multiParts = "test..test.test";
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(multiParts, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("invalid id token not all parts present", e.getMessage());
        }
    }

    @Test
    public void parseIDTokenSignatureValidationFailure() {
        String invalidToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6IjNiY2YwYjNjYzg2MmEwYWM3NzA5MmY3MmI0ZGZkYjIwYTgxMDBkZjAifQ.eyJhdWQiOiI0MDc0MDg3MTgxOTIuYXBwcy5lYmF5LmNvbSIsInN1YiI6ImJTQXE5cEJIV2NFbnJ4IiwiZXhwIjoxNTI3ODMzNTYzLCJpc3MiOiJodHRwczovL29hdXRoLmViYXkuY29tIiwiaWF0IjoxNTI3ODI5OTYzLCJub25jZSI6ImFhYmNlLWRkc2QtZWRmYSIsInByZWZlcnJlZF91c2VybmFtZSI6InRlc3RfdXNlciJ9.XuX3cPtACrwCcpD6O721lMB4I6Me20JTJhIaK1Ov-4Tq4hciK0EAEx-b7FM9_KLYbjMK-bSAq9pBHWcEnrxi2wMoJnXU84WJQMjK_yCYLNnpVxVHqovXMGTjHzMseFZ79md8FH3t3lEeHoPf5YXXOqZwpBhjEcm8Puz2QgAvF1FxLCfeuklfOxTSpBNIHgpd_HNDCWwefIIPz1Pc7kO5w4vmyBpmgB76ygbW_y1luuKbarAaeGgeP-y3t5DBmKE7JsfW9dOts2Aqq_o3s9hG75tjGVFcO7SQihZ2B04lbwyao3DKBJmBXDd7VhIyg6Gn3cT_ZnBUVP0L0g7ox3x06A";
        try {
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(invalidToken, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("signature verification failed", e.getMessage());
        }
    }

    @Test
    public void parseIDTokenMissingHeader() {
        try {
            String multiParts = ".test.test";
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(multiParts, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("invalid id token not all parts present", e.getMessage());
        }
    }

    @Test
    public void parseIdTokenMissingSign() {
        try {
            String multiParts = "test.test.";
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(multiParts, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("invalid id token not all parts present", e.getMessage());
        }
    }

    @Test
    public void parseIdTokenMissingPayload() {
        try {
            String multiParts = "test..test";
            String appId = CredentialUtil.getCredentials(EXECUTION_ENV).get(CredentialUtil.CredentialType.APP_ID);
            validate(multiParts, Collections.singletonList(appId));
            fail("Exception expected");
        } catch (JWTExtractException e) {
            assertEquals("invalid id token not all parts present", e.getMessage());
        }

    }
}
