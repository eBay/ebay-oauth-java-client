package com.ebay.api.client.auth.oauth2;

import com.ebay.api.client.auth.oauth2.model.CredentialConfig;
import com.ebay.api.client.auth.oauth2.model.Environment;
import org.junit.Assert;
import org.junit.Test;

public class CredentialLoadTest {

    @Test
    public void loadByEntity() {

        CredentialConfig config = new CredentialConfig();

        config.setSandbox(new CredentialConfig.EnvironmentInfo("appid", "certid", "devid", "redirect_uri"));

        config.setProduction(new CredentialConfig.EnvironmentInfo("appid1", "certid1", "devid1", "redirect_uri1"));

        CredentialUtil.load(config);

        CredentialUtil.Credentials cs = CredentialUtil.getCredentials(Environment.SANDBOX);
        CredentialUtil.Credentials cp = CredentialUtil.getCredentials(Environment.PRODUCTION);

        String cnf =
            "api.sandbox.ebay.com:\n" +
            "    appid: appid\n" +
            "    certid: certid\n" +
            "    devid: devid\n" +
            "    redirecturi: redirect_uri\n" +
            "api.ebay.com:\n" +
            "    appid: appid1\n" +
            "    certid: certid1\n" +
            "    devid: devid1\n" +
            "    redirecturi: redirect_uri1";

        CredentialUtil.load(cnf);

        CredentialUtil.Credentials cs1 = CredentialUtil.getCredentials(Environment.SANDBOX);
        CredentialUtil.Credentials cp1 = CredentialUtil.getCredentials(Environment.PRODUCTION);

        Assert.assertNotEquals(cs, cs1);
        Assert.assertNotEquals(cp, cp1);

        CredentialUtil.CredentialType appId = CredentialUtil.CredentialType.APP_ID;
        CredentialUtil.CredentialType certId = CredentialUtil.CredentialType.CERT_ID;
        CredentialUtil.CredentialType devId = CredentialUtil.CredentialType.DEV_ID;
        CredentialUtil.CredentialType redirectUri = CredentialUtil.CredentialType.REDIRECT_URI;

        Assert.assertEquals(cs1.get(appId), cs.get(appId));
        Assert.assertEquals(cs1.get(certId), cs.get(certId));
        Assert.assertEquals(cs1.get(devId), cs.get(devId));
        Assert.assertEquals(cs1.get(redirectUri), cs.get(redirectUri));

        Assert.assertEquals(cp1.get(appId), cp.get(appId));
        Assert.assertEquals(cp1.get(certId), cp.get(certId));
        Assert.assertEquals(cp1.get(devId), cp.get(devId));
        Assert.assertEquals(cp1.get(redirectUri), cp.get(redirectUri));

    }

}
