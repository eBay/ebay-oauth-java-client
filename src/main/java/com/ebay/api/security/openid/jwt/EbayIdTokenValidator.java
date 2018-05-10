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

package com.ebay.api.security.openid.jwt;

import com.ebay.api.security.types.EbayIdToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.json.JSONObject;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.List;

import static org.apache.commons.lang3.StringUtils.isEmpty;

public class EbayIdTokenValidator {
    private static final int EXPIRY_BUFFER_IN_MS = 300000;

    public static class JWTExtractException extends RuntimeException {
        public JWTExtractException(String message) {
            super(message);
        }
    }

    public static EbayIdToken validate(String idToken, List<String> trustedClientIds) {
        if (isEmpty(idToken)) {
            throw new JWTExtractException("ID token is null or empty");
        }

        String[] tokens = idToken.split("\\.");

        if (tokens == null || tokens.length != 3) {
            throw new JWTExtractException("invalid id token not all parts present");
        }

        if (isEmpty(tokens[0]) || isEmpty(tokens[1]) || isEmpty(tokens[2])) {
            throw new JWTExtractException("invalid id token not all parts present");
        }

        String keyId = extractKeyId(tokens[0]);
        boolean isValidSignature = verifySign(tokens[2], keyId, (tokens[0] + "." + tokens[1]));

        if (!isValidSignature) {
            throw new JWTExtractException("signature verification failed");
        }

        EbayIdToken tokenInfo = extractPayload(tokens);

        // Casting to long, to prevent the overflow integer space
        DateTime expiresAt = new DateTime(((long) tokenInfo.getExpiresAt() * 1000) + EXPIRY_BUFFER_IN_MS);
        boolean hasExpired = DateTime.now().isAfter(expiresAt);

        if (hasExpired) {
            throw new JWTExtractException("IDToken has expired at: " + expiresAt);
        }
        //TODO: Verify aud with trustedClientIds and iss
        if (!trustedClientIds.contains(tokenInfo.getAudience())) {
            throw new JWTExtractException("IDToken generated for Client: " + tokenInfo.getAudience());
        }

        if (!tokenInfo.getIssuer().equals("oauth.ebay.com")) {
            throw new JWTExtractException("IDToken issued by: " + tokenInfo.getIssuer() + " and not trusted by eBay authentication");
        }
        return tokenInfo;
    }

    private static String extractKeyId(String header) {
        String headerJson = new String(new Base64(true).decode(header));
        JSONObject jsonObject = new JSONObject(headerJson);
        Object kid = jsonObject.get("kid");
        return kid != null ? kid.toString() : null;
    }

    private static boolean verifySign(String signature, String keyId, String data) throws JWTExtractException {
        boolean isValid = false;
        try {
            // Using apache commons base64(true) since it takes care of URL friendly decode.
            byte[] signatureBytes = new Base64(true).decode(signature);
            // Extract cert from esams
            Certificate cert = IdTokenCertificateHolder.getCertificate(keyId);
            // Build signatureObj object
            Signature signatureObj = Signature.getInstance("SHA256withRSA");
            signatureObj.initVerify(cert);
            // Supply the Signature Object With the Data to be Verified
            signatureObj.update(data.getBytes());
            // Verify signatureObj
            isValid = signatureObj.verify(signatureBytes);
        } catch (JWTExtractException e) {
            throw e;
        } catch (SignatureException e) {
            throw new JWTExtractException("Exception verifying signature" + e.getMessage());
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new JWTExtractException("Exception creating signature object: " + e.getMessage());
        } catch (CertificateException | IOException e) {
            throw new JWTExtractException("Exception obtaining certificate: " + e.getMessage());
        }
        return isValid;
    }

    public static EbayIdToken extractPayload(String[] tokens) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            String base64decodedPayload = new String(Base64.decodeBase64(tokens[1]));
            return mapper.readValue(base64decodedPayload, EbayIdToken.class);
        } catch (Exception e) {
            throw new JWTExtractException("Exception converting payload to Token info:" + tokens[1] + e.getMessage());
        }
    }
}
