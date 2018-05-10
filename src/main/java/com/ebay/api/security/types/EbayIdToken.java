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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(Include.NON_NULL)
public class EbayIdToken {
    @JsonProperty("sub")
    private String subject;
    @JsonProperty("iss")
    private String issuer;
    @JsonProperty("aud")
    private String audience;
    @JsonProperty("nonce")
    private String nonce;
    @JsonProperty("iat")
    private long issuedAt;
    @JsonProperty("exp")
    private int expiresAt;
    @JsonProperty("preferred_username")
    private String preferedUserName;

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = issuedAt;
    }

    public int getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(int expiresAt) {
        this.expiresAt = expiresAt;
    }

    public String getPreferedUserName() {
        return preferedUserName;
    }

    public void setPreferedUserName(String preferedUserName) {
        this.preferedUserName = preferedUserName;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("IdToken{");
        sb.append("subject='").append(subject).append('\'');
        sb.append(", issuer='").append(issuer).append('\'');
        sb.append(", audience='").append(audience).append('\'');
        sb.append(", nonce='").append(nonce).append('\'');
        sb.append(", issuedAt=").append(issuedAt);
        sb.append(", expiresAt=").append(expiresAt);
        sb.append(", preferedUserName='").append(preferedUserName).append('\'');
        sb.append('}');
        return sb.toString();
    }
}
