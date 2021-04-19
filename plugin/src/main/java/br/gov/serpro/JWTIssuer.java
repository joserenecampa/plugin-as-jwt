package br.gov.serpro;

import java.io.File;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Base64;
import org.demoiselle.signer.core.extension.BasicCertificate;
import org.demoiselle.signer.core.keystore.loader.KeyStoreLoader;
import org.demoiselle.signer.core.keystore.loader.configuration.Configuration;
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
import org.demoiselle.signer.serpro.desktop.exception.ActionCanceledException;
import org.demoiselle.signer.serpro.desktop.pkcs11info.KeystoreSelection;
import org.demoiselle.signer.serpro.desktop.ui.ListCertificateData;
import org.demoiselle.signer.serpro.desktop.ui.PinHandler;
import org.demoiselle.signer.serpro.desktop.ui.PinHandlerFile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class JWTIssuer extends AbstractCommand<JWTRequest, JWTResponse> {

    private static final Logger logger = LoggerFactory.getLogger(JWTIssuer.class);
    private KeyStore keyStore = null;
    private Configurations configSigner = Configurations.getInstance();
    private JWTResponse response = new JWTResponse();
    private char[] pass = null;
    private static String ACAO = "Emitir Web Token";

    @Override
    public JWTResponse doCommand(JWTRequest request) throws Throwable {
        JWTIssuer.ACAO = "Emitir Web Token";
        try {
            if (request.getHostConnectedPrefix() != null && !request.getHostConnectedPrefix().isEmpty()) {
                JWTIssuer.ACAO = JWTIssuer.ACAO + " - " + request.getHostConnectedPrefix();
            }
            String alias = this.getAlias();
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            BasicCertificate bc = new BasicCertificate(cert);
            Digest digest = DigestFactory.getInstance().factory();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_1);
            String certSha1 = base64Codec(digest.digest(cert.getEncoded()));
            digest = DigestFactory.getInstance().factory();
            digest.setAlgorithm(DigestAlgorithmEnum.SHA_256);
            String certSha2 = base64Codec(digest.digest(cert.getEncoded()));
            long now = System.currentTimeMillis() / 1000L;
            String headerJwt = "{" 
                + "\"alg\":\"RS512\"," 
                + "\"typ\":\"JWT\"" 
                + "" + (!request.isWithCert() ? ",\"x5t\":\"" + certSha1 + "\"," : "") 
                + "" + (!request.isWithCert() ? "\"x5t#S256\":\"" + certSha2 + "\"" : "") 
                + "}";
            String bodyJwt = "{" 
                    + "\"iss\":\"Assinador SERPRO Websocket Service\"," 
                    + "\"iat\":" + now + ","
                    + "\"nbf\":" + now + "," 
                    + "\"exp\":" + (now + 3600) + "," 
                    + "" + (request.isWithData() ? "\"sub\":\"" + bc.getName() + "\"," : "") 
                    + "" + (request.isWithData() ? "\"cpf\":\"" + bc.getICPBRCertificatePF().getCPF() + "\"," : "") 
                    + "" + (request.isWithData() ? "\"email\":\"" + bc.getEmail() + "\"," : "") 
                    + "" + (request.isWithData() ? "\"nascimento\":\"" + bc.getICPBRCertificatePF().getBirthDate() + "\"," : "") 
                    + "" + (request.getAud()!=null&&!request.getAud().trim().isEmpty() ? "\"aud\":\"" + request.getAud() + "\"," : "") 
                    + "\"host\":\"" + request.getHostConnectedPrefix() + "\"" 
                    + "" + (request.isWithCert() ? ",\"x5c\":\"" + base64Codec(cert.getEncoded()) + "\"" : "") 
                    + "}";
            PKCS1Signer signer = PKCS1Factory.getInstance().factory();
            signer.setAlgorithm(SignerAlgorithmEnum.SHA512withRSA);
            signer.setPrivateKey((PrivateKey) this.keyStore.getKey(alias, this.pass));
            String toSigner = base64Codec(headerJwt.getBytes()) + "." + base64Codec(bodyJwt.getBytes());
            byte[] signatureJwt = signer.doDetachedSign(toSigner.getBytes());
            response.setJwt(toSigner + "." + base64Codec(signatureJwt));
            if (!request.isWithCert()) {
                response.setCertificate(base64Codec(cert.getEncoded()));
            } else {
                response.setCertificate(null);
            }
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
        if (configSigner.isUseCertificateFile() || configSigner.isChooseFileCertificate()) {
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
        } else {
            PinHandler pinToken = new PinHandler(JWTIssuer.ACAO, "");
            if (configSigner.isUseNeoId()) {
                Iterator<Entry<String, String>> it = Configuration.getInstance().getDrivers().entrySet().iterator();
                while (it.hasNext()) {
                    Entry<String, String> item = it.next();
                    if (!item.getKey().contains("neoid")) {
                        it.remove();
                    }
                }
            }
            if (configSigner.isSelectedToken()) {
                Iterator<Entry<String, String>> it = Configuration.getInstance().getDrivers().entrySet().iterator();
                while (it.hasNext()) {
                    Entry<String, String> item = it.next();
                    if (!item.getKey().equalsIgnoreCase(configSigner.getTokenNameSelected())) {
                        it.remove();
                    }
                }
            }
            try {
                KeystoreSelection ks = new KeystoreSelection(pinToken, keyStore, null);
                this.keyStore = ks.getKeyStore();
                configSigner.setLastDriverUsed(ks.getLastUsedDriver());
                if (this.keyStore == null) {
                    response.setActionCanceled(true);
                }
            } catch (ActionCanceledException cancel) {
                this.keyStore = null;
            } catch (CertificateException error) {
                this.keyStore = null;
            }
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
