package com.github.yantzu.lighttps;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.webapp.WebAppContext;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.api.client.http.ByteArrayContent;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpRequest;
import com.google.api.client.http.HttpRequestFactory;
import com.google.api.client.http.HttpResponse;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;

public class LighttpsFilterTests {

	private static Server server;
	private static int port = (new Random()).nextInt(1000) + 8000;
	
	@BeforeClass
	public static void beforeClass() throws Exception {
		server = new Server();
		Connector connector = new SelectChannelConnector();

		connector.setPort(port);

		server.setConnectors(new Connector[] { connector });

		WebAppContext webAppContext = new WebAppContext("webapp", "/");

		webAppContext.setDescriptor("src/test/resources/webapp/WEB-INF/web.xml");
		webAppContext.setResourceBase("src/test/webapp");
		webAppContext.setDisplayName("lighttps");
		webAppContext.setClassLoader(Thread.currentThread().getContextClassLoader());
		webAppContext.setConfigurationDiscovered(true);
		webAppContext.setParentLoaderPriority(true);

		server.setHandler(webAppContext);

		server.start();
	}
	
	
	@AfterClass
	public static void afterClass() throws Exception {
		server.stop();
	}
    
    
	private byte[] encryptData(String data) throws UnsupportedEncodingException {
		SecretKeySpec secretKeySpec = new SecretKeySpec("this-is-raw-key1".getBytes("UTF-8"), "AES");

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
			cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
			return cipher.doFinal(data.getBytes());
		} catch (GeneralSecurityException securityExcepiton) {
			throw new IllegalStateException(securityExcepiton);
		}
	}
	
	private String decryptData(byte[] data)throws UnsupportedEncodingException {
		SecretKeySpec secretKeySpec = new SecretKeySpec("this-is-raw-key1".getBytes("UTF-8"), "AES");

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
			cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
			return new String(cipher.doFinal(data), "UTF-8");
		} catch (GeneralSecurityException securityExcepiton) {
			throw new IllegalStateException(securityExcepiton);
		}
	}
	
	
	@Test
	public void testWrongVersion() throws IOException {
		HttpTransport httpTransport = new NetHttpTransport.Builder().build();
		HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
		
		String url = "http://localhost:" + port + "/lighttps";

		HttpRequest httpRequest = requestFactory.buildGetRequest(new GenericUrl(url));
		
		httpRequest.getHeaders().set("X-A-Key", "VX:dCDUIiuMbdLz4HvhdbArkeByFbHSPx88koDmIpOiKd8=");

		try {
			httpRequest.execute();
		} catch (HttpResponseException responseException) {
			Assert.assertEquals(495, responseException.getStatusCode());
		}
	}
	
	
	@Test
	public void testGet() throws IOException {
		String rawUrl = "/targetUrl?targetP=targetV";
		String ef = Base64.encodeBase64String(encryptData(rawUrl));

		HttpTransport httpTransport = new NetHttpTransport.Builder().build();
		HttpRequestFactory requestFactory = httpTransport.createRequestFactory();

		String url = "http://localhost:" + port + "/lighttps?ef=" + ef;

		HttpRequest httpRequest = requestFactory.buildGetRequest(new GenericUrl(url));

		httpRequest.getHeaders().set("X-S-Key", "V2:dCDUIiuMbdLz4HvhdbArkeByFbHSPx88koDmIpOiKd8=");

		HttpResponse httpResponse = httpRequest.execute();
		Assert.assertEquals("resultX", decryptData(toByte(httpResponse.getContent())));
	}
    
	@Test
	public void testPost() throws IOException {
		String rawUrl = "/targetUrl?targetP=targetV";
		String ef = Base64.encodeBase64String(encryptData(rawUrl));
		
		HttpTransport httpTransport = new NetHttpTransport.Builder().build();
		HttpRequestFactory requestFactory = httpTransport.createRequestFactory();
		
		String url = "http://localhost:" + port + "/lighttps?ef=" + ef;
		
		
		HttpRequest httpRequest = requestFactory.buildPostRequest(new GenericUrl(url), new ByteArrayContent("application/octet-stream", encryptData("contentX")));
		httpRequest.getHeaders().set("X-A-Key", "V1:OP6EHjAF1P+B+uTOBpgQ4S7FHqJ1j4/ZcvAtO9N9X4FZshRVaYykJ6kLeeZ1fzW5rylDtyPz+DmEBxQSBIFBMUgGKakAWIqXrzqfunhl0cmcBbSxhSGbuzMv9ofcVsZYz31uOcWxflpbLASc/2d8Gtos6sVcC8076Y/9917xUQWB7zAchy8W+6aV/0IYWYY1CHf63BMuWRsQi0URIaBPix41ZKY97HbAkzSbLo1pcwK2RdZEUKb2hym6WeH0YUPBKOCoE+GtAZdsVqL0b7RbutSLlC97vIQFmsQKI8XCTF3Cwe7rft4I1BDTwM3OjAoJp+Id5wjDwfAss9/yHE9kwQ==");
		HttpResponse httpResponse = httpRequest.execute();
		
		Assert.assertEquals("V2:dCDUIiuMbdLz4HvhdbArkeByFbHSPx88koDmIpOiKd8=", httpResponse.getHeaders().getFirstHeaderStringValue("X-S-Key"));
		
		Assert.assertEquals("resultX", decryptData(toByte(httpResponse.getContent())));
	}
	
	
	private byte[] toByte(InputStream inputStream) throws IOException {
		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

		int nRead;
		byte[] data = new byte[16384];

		while ((nRead = inputStream.read(data, 0, data.length)) != -1) {
			byteArrayOutputStream.write(data, 0, nRead);
		}

		byteArrayOutputStream.flush();

		return byteArrayOutputStream.toByteArray();
	}
	
//	@Test
//	public void testEncry() throws IOException {
//		FileInputStream fis = new FileInputStream("D:\\doc\\UXIP\\压力测试\\batch_new.gz");
//		byte[] orignal = IOUtils.toByteArray(fis);
//		
//		ByteArrayOutputStream baos = new ByteArrayOutputStream();
//		IOUtils.write("--------------------------5b258d945167c31e\r\n", baos);
//		IOUtils.write("Content-Disposition: form-data; name=\"data\"; filename=\"batch_new.gz\"\r\n", baos);
//		IOUtils.write("Content-Type: application/octet-stream\r\n\r\n", baos);
//		IOUtils.write(orignal, baos);
//		IOUtils.write("\r\n--------------------------5b258d945167c31e--\r\n\r\n", baos);
//		
//		byte[] result = encryptData(baos.toByteArray());
//		
//		FileOutputStream fos = new FileOutputStream("D:\\doc\\UXIP\\压力测试\\lighttps\\batch_new.gz");
//		IOUtils.write(result, fos);
//
//	}
}
