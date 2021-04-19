package br.gov.serpro;

import org.demoiselle.signer.serpro.desktop.web.requestResponse.Request;

public class JWTRequest extends Request {

    private boolean withCert = false;
    private boolean withData = false;
    private String aud = "";

    public boolean isWithCert() {
        return withCert;
    }

    public void setWithCert(boolean withCert) {
        this.withCert = withCert;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public boolean isWithData() {
        return withData;
    }

    public void setWithData(boolean withData) {
        this.withData = withData;
    }
}
