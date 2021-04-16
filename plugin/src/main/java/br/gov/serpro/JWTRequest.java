package br.gov.serpro;

import org.demoiselle.signer.serpro.desktop.web.requestResponse.Request;

public class JWTRequest extends Request {

    private boolean withCert = false;

    public boolean isWithCert() {
        return withCert;
    }

    public void setWithCert(boolean withCert) {
        this.withCert = withCert;
    }
    
}
