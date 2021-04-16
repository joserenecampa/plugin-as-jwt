package br.gov.serpro;

import org.demoiselle.signer.serpro.desktop.web.requestResponse.Response;

public class JWTResponse extends Response {

    private String jwt = "";
    private String certificate = "";
    
    public JWTResponse() {
        super();
    }
    
    public JWTResponse(JWTRequest request) {
        super(request);
    }

    public String getJwt() {
        return jwt;
    }

    public void setJwt(String jwt) {
        this.jwt = jwt;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }
}
