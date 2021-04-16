package br.gov.serpro;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.factory.KeyStoreLoaderFactory;
import org.demoiselle.signer.core.util.Base64Utils;
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
            String headerJwt = "{\"alg\":\"RS512\",\"typ\":\"JWT\"}";
            String alias = this.getAlias();
			X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
			BasicCertificate bc = new BasicCertificate(cert);
            String bodyJwt = "{\"sub\":\"" + bc.getICPBRCertificatePF().getCPF() + "\",\"name\":\"" + bc.getName() + "\"}";
            PKCS1Signer signer = PKCS1Factory.getInstance().factory();
            signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
            signer.setPrivateKey((PrivateKey)this.keyStore.getKey(alias, this.pass));
            String toSigner = Base64Utils.base64Encode(headerJwt.getBytes())+"."+Base64Utils.base64Encode(bodyJwt.getBytes());
            byte[] signatureJwt = signer.doDetachedSign(toSigner.getBytes());
            response.setJwt(toSigner+"."+Base64Utils.base64Encode(signatureJwt));
        } catch (Throwable error) {
            logger.error("Erro ao assinar token", error);
            response.setJwt(error.getMessage());
        }
        return response;
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
