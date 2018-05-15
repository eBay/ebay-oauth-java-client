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
import com.ebay.api.security.types.EbayIdToken;
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

import java.io.FileNotFoundException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.ebay.api.security.CredentialLoaderTestUtil.CRED_PASSWORD;
import static com.ebay.api.security.CredentialLoaderTestUtil.CRED_USERNAME;
import static org.junit.Assert.*;

public class EbayIdTokenValidatorTest {
    //NOTE: Change this env to Environment.PRODUCTION to run this test in PRODUCTION
    private static final Environment EXECUTION_ENV = Environment.PRODUCTION;

    @BeforeClass
    public static void testSetup() {
        CredentialLoaderTestUtil.commonLoadCredentials(EXECUTION_ENV);
        assertNotNull(CredentialLoaderTestUtil.CRED_USERNAME, "Please check if test-config.yaml is setup correctly");
        assertNotNull(CredentialLoaderTestUtil.CRED_PASSWORD, "Please check if test-config.yaml is setup correctly");
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
        String appId = CredentialHelper.getCredentials(EXECUTION_ENV).get(CredentialHelper.CredentialType.APP_ID);
        EbayIdToken ebayIdToken = EbayIdTokenValidator.validate(idToken, Arrays.asList(appId));
        assertNotNull(ebayIdToken);
        assertEquals(CRED_USERNAME, ebayIdToken.getPreferedUserName());
        assertEquals("oauth.ebay.com", ebayIdToken.getIssuer());
        assertEquals(nonce, ebayIdToken.getNonce());
        assertEquals(appId, ebayIdToken.getAudience());
		assertTrue(ebayIdToken.getIssuedAt() < (new Date().getTime() / 1000));
        assertTrue(ebayIdToken.getExpiresAt() > (new Date().getTime() / 1000));
    }

    public String getIdTokenResponseUrl(String nonce) throws InterruptedException {
        // Optional, if not specified, WebDriver will search your path for chromedriver.
        System.setProperty("webdriver.chrome.driver", "/usr/local/bin/chromedriver");

        WebDriver driver = new ChromeDriver();
        IEbayAuthApi authApi = new EbayAuthApi();
        String idTokenUrl = authApi.generateIdTokenUrl(EXECUTION_ENV, Optional.of("current-page"), nonce);

        driver.get(idTokenUrl);
        Thread.sleep(5000);

        WebElement userId = (new WebDriverWait(driver, 10))
                .until(ExpectedConditions.visibilityOf(driver.findElement(By.cssSelector("input[type='text']:not([name='userid_otp']):not([name='otp'])"))));

        WebElement password = driver.findElement(By.cssSelector("input[type='password']"));
        userId.sendKeys(CRED_USERNAME);
        password.sendKeys(CRED_PASSWORD);
        driver.findElement(By.name("sgnBt")).submit();

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

//
//	@Test
//	public void parseIDTokenEmptry() throws Exception {
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// validate idtoken
//		try {
//			extractor.parse("");
//		}  catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//	}
//
//	@Test
//	public void parseIDTokenMissingHeader() throws Exception {
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// validate idtoken
//		try {
//			extractor.parse("dummyPayload.dummySign");
//		}  catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//	}
//
//	@Test
//	public void parseIdTokenMissingSign() {
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// validate idtoken
//		try {
//			extractor.parse("dummyHeader.dummy.");
//		}  catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//	}
//
//	@Test
//	public void parseIdTokenMissingPayload() {
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// validate idtoken
//		try {
//			extractor.parse("dummyHeader..");
//		}  catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//	}
//
//	@Test
//	public void parseIDTokenExpired() throws Exception {
//
//		IDTokenInfo inputClaims =  buildClaims();
//
//		DateTime currentTime = DateTime.now(DateTimeZone.UTC);
//		DateTime expiryTime = currentTime.minusHours(1);
//		long expiryInMs = expiryTime.getMillis();
//		inputClaims.setExpiryInSecs(expiryInMs/1000);
//
//		Map<String, Object> claims = convertToMap(inputClaims);
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// generate IDToken
//		String idToken = extractor.generateIDToken(claims);
//
//		// validate idtoken
//		try {
//			extractor.parse(idToken);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//	}
//
////	@Test
////	public void parseIDTokenExpiredCreatedInOAuthWebApp() throws Exception {
////
////		String idToken = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJvYXV0aC5lYmF5LmNvbSIsInN1YiI6ImR1bW15IiwiaWF0IjoxNTA3NTk0NTAxLCJleHAiOjE1MDc1OTgxMDF9.GdUVsQRRudLzaLAE5HUclpwGzt51O8fLYZkozhODAkJEPqCF6R79221zTwlEDIQG4o2Oj2AZD2HF8csVDrJA5uBrOuj-ZvvMCrRvIdwubMeEa63RTDimdgozdtysiEMgkpl5qTelHEdTESciOnXEWHaPpW_9PQxrExJ-BTMAYYB_WZBFaUIZEOFChAYKrpzdmnj9h9EFiF33WlyYuyawDuhIUvV2wSJmCyllGJHeiHrV_5GKdmi59LJqvYB-1NQ9ovNZtmtLALTc8GGIxDzR5rEiAbqCd-IQa71Dt58u0L1neX0U8Stg2Dt-fSpJK2MXHH0eU9TqWiWPfmJ_4rMdkg";
////		DefaultJwtParser extractor = new DefaultJwtParser();
////
////		// validate idtoken
////		try {
////			extractor.parse(idToken);
////		} catch (JWTExtractException e) {
////			e.printStackTrace();
////			Assert.fail("NO exception expected but got one");
////			return;
////		}
////
////
////	}
//
//	@Test
//	public void parseInvalidSign() throws JWTExtractException {
//
//		String inputToken = "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE1MDcxNDIxMjk1NzAsInN1YiI6IlFJQlVTIEJ1eWVyIiwibm9uY2UiOiJzb21ldmFsdWUiLCJlbWFpbCI6ImlhZm1vYmlsZTAwMUB1bmljb3JuLnFhLmViYXkuY29tIiwiYXVkIjoiQWRtaW5BcHAiLCJpc3MiOiJodHRwczovL29wZW5pZC5jMmlkLmNvbSIsImp0aSI6IjIwMTctMTAtMDRUMTA6MzU6MjkuNTg4LTA3OjAwNzY0MTE2Njk2OTUyMTIiLCJhY3IiOiJjMmlkLmxvYS5oaXNlYyJ9.l6nrNLLLqmUGEFs2v0rCR770Gg5gToclYOweGvud2iajus3zQrI8jV7sI5uKf0h977Eo4ZLsxUDesooyaQHPXlpr7QP-8pKk_F3LNOgpGe92TbDaBbplyXHqG2dti6AbkrUejHY8VdlkQbKTFQOVgvmA115n1e88yEm0DkDYqzaZJ8YJyvwkQhNbSEpiTt6Pn4wh-zkgypgyOYfNNKduheGXO45jgFLTYpcQjAs2ylMmMSrxvq0TUAS_DFYhqBvNrpu77dxH-2mpt4WmEfUPBooEEWXIA-4OZHwsP_AmHb2RzCn5ZhOvrns7bUke5UjZWf2Fn6pQdE22dawtL4Xm";
//
//		DefaultJwtParser extractor = partialMockBuilder(DefaultJwtParser.class).addMockedMethod("verifySign").createMock();
//
//		EasyMock.expect(extractor.verifySign(EasyMock.anyObject(byte [].class), EasyMock.anyObject(String.class))).andReturn(false);
//
//		// validate idtoken
//		try {
//			extractor.parse(inputToken);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//	}
//
//	@Test
//	public void getKeyThrowsEsamsException() throws JWTExtractException, EsamsException {
//
//		DefaultJwtParser extractor = partialMockBuilder(DefaultJwtParser.class).addMockedMethod("getNameService").createMock();
//
//		NameService nameService = createMock(NameService.class);
//
//		EasyMock.expect(nameService.getKeyPair(DefaultJwtParser.KEY_PAIR_NAME, NameService.VERSION_LAST_ENABLED)).andThrow(new EsamsException("dummyException"));
//
//		// validate idtoken
//		try {
//			extractor.getKey();
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//	}
//
//	@Test
//	public void buildSignatureThrowsException() throws Exception {
//
//		DefaultJwtParser extractor = partialMockBuilder(DefaultJwtParser.class).addMockedMethod("getSignature").createMock();
//
//		Certificate certificate = createMock(Certificate.class);
//		Signature signature = createMock(Signature.class);
//
//		signature.initVerify(certificate);
//		EasyMock.expectLastCall().andThrow(new InvalidKeyException("dummyException"));
//
//		try {
//			extractor.buildSignature(certificate);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//	}
//
//	@Test
//	public void extactPayloadThrowsException() throws JWTExtractException {
//
//
//		DefaultJwtParser defaultJwtParser = new DefaultJwtParser();
//		String [] tokens = {"dummyHeader","dummyPayload",""};
//
//		try {
//			defaultJwtParser.extactPayload( tokens);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//
//
//	}
//
//	@Test
//	public void verifySignThrowsException() throws JWTExtractException {
//
//		DefaultJwtParser defaultJwtParser = partialMockBuilder(DefaultJwtParser.class).addMockedMethod("getCertFromESAMS").createMock();
//
//		EasyMock.expect(defaultJwtParser.getCertFromESAMS()).andThrow(new JWTExtractException("dummyException"));
//
//
//		try {
//			defaultJwtParser.verifySign(null, null);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//
//
//	}
//
//	@Test
//	public void verifySignThrowsNPE() throws JWTExtractException {
//
//		DefaultJwtParser defaultJwtParser = new DefaultJwtParser();
//
//
//		try {
//			defaultJwtParser.verifySign(null, null);
//		} catch (JWTExtractException e) {
//			return;
//		}
//
//		Assert.fail("expected exception but did not get one");
//
//
//
//	}
//
//	private Map<String, Object> convertToMap(IDTokenInfo inputClaims) {
//		ObjectMapper mapper = new ObjectMapper();
//
//		// Convert POJO to Map
//		Map<String, Object> claims =
//		    mapper.convertValue(inputClaims, new TypeReference<Map<String, Object>>() {});
//		return claims;
//	}
//
//	private IDTokenInfo buildClaims() {
//
//		IDTokenInfo inputClaims = new IDTokenInfo();
//
//		inputClaims.setAudience("shipping");
//
//		DateTime currentTime = DateTime.now(DateTimeZone.UTC);
//		DateTime expiryTime = currentTime.plusHours(1);
//		long expiryInMs = expiryTime.getMillis();
//		inputClaims.setExpiryInSecs(expiryInMs/1000);
//
//		inputClaims.setIssuer("ebay");
//
//		long randomNum = (long) (Math.random() * 100000000000000L);
//		inputClaims.setNonce(Long.valueOf(randomNum).toString());
//
//		inputClaims.setSubject("dummyUserName");
//
//		return inputClaims;
//	}
//
//	@Test
//	public void getDefaultParser() throws Exception {
//		JWTParser jwtParser = JWT.getDefaultParser();
//		org.junit.Assert.assertNotNull(jwtParser);
//	}

}
