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

import com.ebay.api.security.openid.jwt.EbayIdTokenValidator;
import org.junit.Test;

import java.util.Arrays;

public class EbayIdTokenValidatorTest{

    @Test
    public void verify(){
        String s = "eyJraWQiOiI2NzYwMjFiYjdkY2ViM2NmZmE1NGQ0NDZlMjdiNjQwNDRjMTE2N2Y2ZDZlMWVlOGViNjQzYmUzODA4NTZlNmZiIiwiYWxnIjoiUlMyNTYifQ.eyJwcmVmZXJyZWRfdXNlcm5hbWUiOiJzZW5nb3BhbHRlc3RfODkxOCIsImlzcyI6Im9hdXRoLmViYXkuY29tIiwic3ViIjoiVVRIOEpzNXFSUjIiLCJhdWQiOiJTb25hbVJ1ZC1zdGFnaW5ndC1TQlgtOWYxMjNmZmE0LTgxNDZkNzIxIiwiaWF0IjoxNTIzMzkwNzUzLCJleHAiOjE1MjMzOTQzNTMsIm5vbmNlIjoiMTIzNCJ9.jR6nG6qRP4ps0Z4fQb-RLIcdugvkw8NokO24DN_JH-Fd_ONOBOv2Weh8Z9egv55aH9M_gXzpk8xPtxYNH3mH25cppP2pY-kBdbvmtexH9LdKygqdDLvHFqdGp-Amg7CG0bSKCQ-zDPHj1b4SWWEWTWauEepGhV4fft6ORo6-EzDo77D8CsmncU2fAZrILav7iDX6G4PhpH7JPPlw9y_3yGi6uiRotx6H6IT-tjYdDrCx7Q9CHgzRMCzOlzVbOoytvOsnVXv4Qokr3eU0CUoxgxnNuWtod3VvHgF27jfN5CO7s7eys43viRNwWxOj1Pn9CuvVOBAe3H8DFLpu4IRKLw";
        System.out.println(EbayIdTokenValidator.validate(s,Arrays.asList(new String[]{"SonamRud-stagingt-SBX-9f123ffa4-8146d721"})));
        System.out.println(EbayIdTokenValidator.validate(s,Arrays.asList(new String[]{"SonamRud-stagingt-SBX-9f123ffa4-8146d721"})));
    }
//
//	@BeforeClass
//	public static void init() throws MalformedURLException {
//		String userDir = "user.dir";
//		String pathToMETAINF = "src/test/resources/META-INF";
//
//		String currentDirectory = System.getProperty(userDir);
//		File curDir = new File(currentDirectory);
//		File resourceDir = new File(curDir, pathToMETAINF);
//		File configDir = new File(resourceDir, "config");
//		RuntimeContext.setConfigRoot(resourceDir.toURI().toURL());
//		RuntimeContext.setResourceRoot(configDir.toURI().toURL());
//		RuntimeContext.setExternalConfigRoot(configDir.toURI().toURL());
//
//		IRaptorContext raptorContext = new MockRaptorContext();
//		RaptorContextFactory.setCtx(raptorContext);
//		RaptorESamsHelper.getInstance();
//		NameServiceImpl.initialize();
//	}
//
//	@Test
//	public void parse() throws Exception {
//
//		IDTokenInfo inputClaims =  buildClaims();
//
//		Map<String, Object> claims = convertToMap(inputClaims);
//
//		DefaultJwtParser extractor = new DefaultJwtParser();
//
//		// generate IDToken
//		String idToken = extractor.generateIDToken(claims);
//
//		// validate idtoken
//		IDTokenInfo jwtTokenInfo = extractor.parse(idToken);
//
//		// ID Token
//		Assert.assertEquals(inputClaims.getSubject(), jwtTokenInfo.getSubject());
//		Assert.assertEquals(inputClaims.getIssuer(), jwtTokenInfo.getIssuer());
//		Assert.assertEquals(inputClaims.getNonce(), jwtTokenInfo.getNonce());
//		Assert.assertEquals(inputClaims.getAudience(), jwtTokenInfo.getAudience());
//		Assert.assertEquals(inputClaims.getIssedAtInMilSecs(), jwtTokenInfo.getIssedAtInMilSecs());
//		Assert.assertEquals(inputClaims.getPreferedUserName(), jwtTokenInfo.getPreferedUserName());
//		Assert.assertEquals(inputClaims.getExpiryInMilSecs(), jwtTokenInfo.getExpiryInMilSecs());
//
//	}
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
