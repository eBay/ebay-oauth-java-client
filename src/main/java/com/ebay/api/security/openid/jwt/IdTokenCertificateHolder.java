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

package com.ebay.api.security.openid.jwt;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class IdTokenCertificateHolder {
    private static final Logger logger = LoggerFactory.getLogger(IdTokenCertificateHolder.class);
    private static final Map<String, X509Certificate> CERT_HOLDER_MAP = new HashMap<>();
    private static final String CERTIFICATE_URL = "https://auth.ebay.com/oauth2/certs/v1/pem";
    private static final Integer DEFAULT_CERT_EXPIRATION_IN_SECS = 86400;
    private static final int BUFFER_TIME_FOR_REFRESH_IN_SECS = 300;
    private static DateTime expiresAt;
    private static final Pattern MAX_AGE_REGEX = Pattern.compile("^.*max-age=(\\d+)\\,.*$");
    private static AtomicBoolean locked = new AtomicBoolean(false);

    private static void refreshCertificates() throws IOException, CertificateException {
        if (locked.compareAndSet(false, true)) {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder().url(CERTIFICATE_URL).get().build();
            Response response = client.newCall(request).execute();

            CertificateFactory factory = CertificateFactory.getInstance("X.509");

            if (response.isSuccessful()) {
                JSONObject jsonObject = new JSONObject(response.body().string());
                CERT_HOLDER_MAP.clear();
                for (String key : jsonObject.keySet()) {
                    String certStr = jsonObject.get(key).toString();
                    X509Certificate x509Cert = (X509Certificate) factory.generateCertificate(
                            new ByteArrayInputStream(org.apache.commons.codec.binary.StringUtils.getBytesUtf8(certStr)));
                    CERT_HOLDER_MAP.put(key, x509Cert);
                    calculateExpiresAt(response.header("Cache-Control"));
                }
            } else {
                logger.error("Error in response for Certificate URL: " + response.toString());
            }
            //unlock
            locked.compareAndSet(true, false);
        }
    }

    private static void calculateExpiresAt(String headerValue) {
        //Refer to specification here - https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control
        Integer expiresInSecs = DEFAULT_CERT_EXPIRATION_IN_SECS;
        if (headerValue != null && headerValue.contains("max-age=")) {
            // Making it lower case to ensure the regex can match the characters
            // We are interested only in the integer part anyway
            Matcher matcher = MAX_AGE_REGEX.matcher(headerValue.toLowerCase());
            if (matcher.matches()) {
                String maxAgeStr = matcher.group(1);
                if (StringUtils.isNumeric(maxAgeStr)) {
                    expiresInSecs = Integer.valueOf(maxAgeStr);
                }
            }
            // Expiring before the actual max-age by a buffer
            expiresAt = DateTime.now().plusSeconds(expiresInSecs - BUFFER_TIME_FOR_REFRESH_IN_SECS);
        }
    }

    public static Certificate getCertificate(String keyId) throws IOException, CertificateException {
        if (CERT_HOLDER_MAP.isEmpty() || expiresAt == null || DateTime.now().isAfter(expiresAt)) {
            refreshCertificates();
        }

        return CERT_HOLDER_MAP.get(keyId);
    }
}