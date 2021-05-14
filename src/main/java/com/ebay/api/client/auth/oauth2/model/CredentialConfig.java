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

package com.ebay.api.client.auth.oauth2.model;

public class CredentialConfig {

    public static class EnvironmentInfo {

        private String appId;

        private String certId;

        private String devId;

        private String redirectUri;

        public EnvironmentInfo(String appId, String certId, String devId, String redirectUri) {
            this.appId = appId;
            this.certId = certId;
            this.devId = devId;
            this.redirectUri = redirectUri;
        }

        public String getAppId() {
            return appId;
        }

        public void setAppId(String appId) {
            this.appId = appId;
        }

        public String getCertId() {
            return certId;
        }

        public void setCertId(String certId) {
            this.certId = certId;
        }

        public String getDevId() {
            return devId;
        }

        public void setDevId(String devId) {
            this.devId = devId;
        }

        public String getRedirectUri() {
            return redirectUri;
        }

        public void setRedirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
        }
    }

    private EnvironmentInfo sandbox;

    private EnvironmentInfo production;

    public EnvironmentInfo getSandbox() {
        return sandbox;
    }

    public void setSandbox(EnvironmentInfo sandbox) {
        this.sandbox = sandbox;
    }

    public EnvironmentInfo getProduction() {
        return production;
    }

    public void setProduction(EnvironmentInfo production) {
        this.production = production;
    }

}
