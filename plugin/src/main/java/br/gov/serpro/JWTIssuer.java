package br.gov.serpro;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;

import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.cryptography.Digest;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.cryptography.factory.DigestFactory;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.factory.PKCS1Factory;
import org.demoiselle.signer.policy.impl.cades.pkcs1.PKCS1Signer;
import org.demoiselle.signer.serpro.desktop.Configurations;
import org.demoiselle.signer.serpro.desktop.command.AbstractCommand;
import org.demoiselle.signer.serpro.desktop.command.cert.Certificate;
import org.demoiselle.signer.serpro.desktop.command.cert.ListCerts;
import org.demoiselle.signer.serpro.desktop.command.cert.ListCertsRequest;
import org.demoiselle.signer.serpro.desktop.command.cert.ListCertsResponse;
import org.demoiselle.signer.serpro.desktop.ui.ListCertificateData;
import org.demoiselle.signer.serpro.desktop.ui.PinHandlerFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JWTIssuer extends AbstractCommand<JWTRequest, JWTResponse> {

    private static final Logger logger = LoggerFactory.getLogger(JWTIssuer.class);
    private KeyStore keyStore = null;
    private Configurations configSigner = Configurations.getInstance();
    private JWTResponse response = new JWTResponse();
    private char[] pass = null;
    private static final String ACAO = "Emitir Web Token";

    @Override
    public JWTResponse doCommand(JWTRequest request) throws Throwable {
        try {
            String alias = this.getAlias();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			BasicCertificate bc = new BasicCertificate(cert);
            Digest digest = DigestFactory.getInstance().factory();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_1);
            String certSha1 = base64Codec(digest.digest(cert.getEncoded()));
            long now = System.currentTimeMillis() / 1000L;
            String headerJwt = "{"+
                            "\"alg\":\"RS512\","+
                            "\"typ\":\"JWT\","+
                            "\"x5t\":\"" + certSha1 + "\""+
                            "}";
            String bodyJwt = "{"+
                             "\"iss\":\"Assinador SERPRO Websocket Service\"," +
                             "\"iat\":" + now +  "," +
                             "\"nbf\":" + now +  "," +
                             "\"exp\":" + (now+3600) +  "," +
                             "\"prn\":\"" + bc.getICPBRCertificatePF().getCPF() + "\","+
                             ""+(request.isWithCert()?"\"crt\":\"" + base64Codec(cert.getEncoded()) + "\",":"")+
                             "\"sub\":\"" + bc.getName() + "\""+
                             "}";
            PKCS1Signer signer = PKCS1Factory.getInstance().factory();
            signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
            signer.setPrivateKey((PrivateKey)this.keyStore.getKey(alias, this.pass));
            String toSigner = base64Codec(headerJwt.getBytes())+"."+base64Codec(bodyJwt.getBytes());
            byte[] signatureJwt = signer.doDetachedSign(toSigner.getBytes());
            response.setJwt(toSigner+"."+base64Codec(signatureJwt));
            response.setCertificate(base64Codec(cert.getEncoded()));
        } catch (Throwable error) {
            logger.error("Erro ao assinar token", error);
            response.setJwt(error.getMessage());
        }
        return response;
    }

    private String base64Codec(byte[] content) {
        return Base64.encodeBase64URLSafeString(content);
    }

    private void loadKeyStore() {
        try {
            File filep12 = new File(configSigner.getCertificateFilePath());
            if (configSigner.isSaveCertificateFilePass()) {
                this.pass = configSigner.getCertificateFilePass();
            } else {
                PinHandlerFile pinFile = new PinHandlerFile(JWTIssuer.ACAO, null);
                pinFile.init();
                if (!pinFile.getActionCanceled()) {
                    this.pass = pinFile.getPwd();
                } else {
                    throw new RuntimeException("Cancelada pelo usuário");
                }
            }
            configSigner.setLastDriverUsed(filep12.getAbsolutePath());
            KeyStoreLoader loader = KeyStoreLoaderFactory.factoryKeyStoreLoader(filep12);
            this.keyStore = loader.getKeyStore(String.copyValueOf(this.pass));
        } catch (Throwable error) {
            logger.error("Erro ao carregar KeyStore", error);
        }
    }

    public String getAlias() throws Throwable {
        String result = null;
        ListCertsRequest requestCert = new ListCertsRequest();
        requestCert.setUseCertFor(JWTIssuer.ACAO);
        ListCerts ls = new ListCerts();
        this.loadKeyStore();
        ListCertsResponse lr = ls.doCommand(requestCert, this.keyStore);
        if (lr.getCertificates().isEmpty()) {
            logger.error("Retornou getCertificates Vazio");
            throw new RuntimeException(
                    "Nenhum certificado foi encontrado, verifique se seu token esta conectar ao computador, caso esteja feche e abra novamente o assinador.");
        }
        if (lr.getCertificates().size() > 1) {
            ListCertificateData lcd = new ListCertificateData(lr);
            lcd.init();
            result = lcd.getAlias();
            if (result == null || result.equals("")) {
                response.setActionCanceled(true);
                return null;
            }
        } else {
            ArrayList<Certificate> list = (ArrayList<Certificate>) lr.getCertificates();
            Certificate cert = list.iterator().next();
            result = cert.getAlias();
        }
        return result;
    }

    @Override
    public String getCommandName() {
        return "jwt";
    }

}
