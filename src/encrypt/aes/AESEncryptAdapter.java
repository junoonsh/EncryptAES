package encrypt.aes;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.Credentials;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.SingleClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;

public class AESEncryptAdapter {
	private static boolean USE_PROXY = true;
	private static boolean USE_PROXY_AUTH = false;

	public static String sURL = "www";
	
	public static String nInstitutionID = "9289202";
	private static String sEncryptionKey = "njdsljkd876jkdsksh";
	
	private static String sInitializationVector = "937320932109";
    public static String sLoginID = "testuser";
    public static String sCompanyID = "comp8356";
	public static String login() {

        
        String sCredentials = nInstitutionID + ";" + new SimpleDateFormat("yyyyMMdd HH:mm:ss" ).format(new Date());
        String sEncryptedCredentials = encryptCredentials( sCredentials, sEncryptionKey, sInitializationVector );

        String xmlSessionRequest = getSessionRequest( nInstitutionID, sInitializationVector, sEncryptedCredentials, sLoginID, sCompanyID );
        System.out.println("xmlSessionRequest: " + xmlSessionRequest);
        String sMessagePostURL = "https://" + sURL + ".example.com/Messaging/MessageHandler.aspx";
        String sSessionID = getSessionID( sMessagePostURL, xmlSessionRequest );

        String sLoginURL = "https://" + sURL + ".example.com/loginconfirm.asp?instid=" + nInstitutionID + "&op=Login&Method=Session&CompanyID=" + sCompanyID;
        return sSessionID;
	}
	
	
	private static String makeHttpRequest(String sMessagePostURL, String xmlSessionRequest) {
		DefaultHttpClient httpClient = createHttpClient(443);

		HttpPost req = new HttpPost(sMessagePostURL); 
		try {
			req.setEntity(new StringEntity(xmlSessionRequest));
		} catch (UnsupportedEncodingException e1) {
			e1.printStackTrace();
		}
		String resp = null;
		try {
			ResponseHandler<String> responseHandler = new BasicResponseHandler();
			resp = httpClient.execute(req, responseHandler);
			System.out.println("response:" + resp);
		} catch (ClientProtocolException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return resp;
	}
	
	private static String getSessionID(String sMessagePostURL, String xmlSessionRequest) {
		String sessionId = null;
		String resp = makeHttpRequest(sMessagePostURL, xmlSessionRequest);
		
		// TODO Use XPath expression to retrieve the sessionId. DO NOT use regex. 
		Pattern pattern = Pattern.compile("<SessionID>(.*)</SessionID>");
		Matcher matcher = pattern.matcher(resp);
		if (matcher.find()) {
			sessionId = matcher.group(1);
		}

		return sessionId;
	}
	
	private static String getSessionRequest(String nInstitutionID,
			String sInitializationVector, String sEncryptedCredentials,
			String sLoginID, String sCompanyID) {
		String requestID = "0";
		String requestXML = readFile("SessionRequest.xml");
		requestXML = StringUtils.replace(requestXML, "[InstitutionID]", nInstitutionID);
		requestXML = StringUtils.replace(requestXML, "[IV]", sInitializationVector);
		requestXML = StringUtils.replace(requestXML, "[AuthToken]", sEncryptedCredentials);
		requestXML = StringUtils.replace(requestXML, "[RequestID]", requestID);
		requestXML = StringUtils.replace(requestXML, "[CompanyID]", sCompanyID);
		requestXML = StringUtils.replace(requestXML, "[LoginID]", sLoginID);
		return requestXML;
	}
	
	public static String readFile(String fileName) {
	    StringBuilder text = new StringBuilder();
	    String NL = System.getProperty("line.separator");
	    Scanner scanner;
		try {
			scanner = new Scanner(AESEncryptAdapter.class.getResourceAsStream(fileName));
		    try {
			      while (scanner.hasNextLine()){
			        text.append(scanner.nextLine() + NL);
			      }
			    }
			    finally{
			      scanner.close();
			    }
		} catch (Exception e) {
			e.printStackTrace();
		}

	    return text.toString();
	}
	public static String encryptCredentials(String sCredentials,
			String sEncryptionKey, String sInitializationVector) {
		
		byte[] encryptionKeyByte=  sEncryptionKey.getBytes();

		SecretKeySpec skeySpec = new SecretKeySpec(encryptionKeyByte, "AES");
		Cipher cipher;
		byte[] encrypted = null;
		try {
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(
					sInitializationVector.getBytes()));
			encrypted = cipher.doFinal(sCredentials.getBytes());
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
		   
	   return new String(Base64.encodeBase64(encrypted));
	}
	private static DefaultHttpClient createHttpClient(int port) {   
		try {    
			java.lang.System.setProperty(      "sun.security.ssl.allowUnsafeRenegotiation", "true");      
			X509TrustManager trustManager = new X509TrustManager() {     
				public void checkClientTrusted(X509Certificate[] chain,       String authType) throws CertificateException {      
					// Don't do anything.     
					}       
				public void checkServerTrusted(X509Certificate[] chain,       String authType) throws CertificateException {      
					// Don't do anything.     
					}       
				public X509Certificate[] getAcceptedIssuers() {      
					// Don't do anything.      
					return null;     }    
			};      
					
			SSLContext sslContext = SSLContext.getInstance("SSL");    
			sslContext.init(null, new TrustManager[] { trustManager }, new SecureRandom());      
			SSLSocketFactory sf = new SSLSocketFactory(sslContext);    
			sf.setHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);      
			Scheme httpsScheme = new Scheme("https", sf, port);    
			
			SchemeRegistry schemeRegistry = new SchemeRegistry();    
			schemeRegistry.register(new Scheme("http", PlainSocketFactory.getSocketFactory(), 80)); 
			schemeRegistry.register(httpsScheme);      
			HttpParams params = new BasicHttpParams();    
			ClientConnectionManager cm = new SingleClientConnManager(params, schemeRegistry);   
					
			return new DefaultHttpClient(cm, params);   
		} catch (Exception ex) {       
			return null;   
		}
	}


	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
			AESEncryptAdapter.login();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
