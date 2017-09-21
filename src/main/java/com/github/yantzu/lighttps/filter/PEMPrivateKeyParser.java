package com.github.yantzu.lighttps.filter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Security;

import org.bouncycastle.openssl.PEMReader;

public class PEMPrivateKeyParser implements PrivateKeyParser {
	
	static {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
//	private String toString(InputStream inputStream) {
//		Scanner scanner = new Scanner(inputStream);
//		scanner.useDelimiter("\\A");
//		try {
//			return scanner.hasNext() ? scanner.next() : "";
//		} finally {
//			scanner.close();
//		}
//	}
	
	@Override
	public PrivateKey parse(InputStream inputStream) {
		PEMReader pemReader = new PEMReader(new InputStreamReader(inputStream));
		try {
			KeyPair keyPair = (KeyPair) pemReader.readObject();
			return keyPair.getPrivate();
		} catch (IOException ioException) {
			throw new RuntimeException(ioException);
		} finally {
			try {
				pemReader.close();
			} catch (IOException e) {
				// ignore
			}
		}
		
//		String keyString = toString(inputStream);
//		
//		keyString = keyString.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
//		keyString = keyString.replace("-----END RSA PRIVATE KEY-----", "");
//		byte[] encoded = Base64.decodeBase64(keyString);
//		KeyFactory kf;
//		try {
//			kf = KeyFactory.getInstance("RSA");
//		} catch (NoSuchAlgorithmException noSuchAlgorithmException) {
//			throw new IllegalStateException(noSuchAlgorithmException);
//		}
//		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(encoded);
//		try {
//			return kf.generatePrivate(keySpec);
//		} catch (InvalidKeySpecException invalidKeySpecException) {
//			throw new IllegalArgumentException("Invalid Certificate", invalidKeySpecException);
//		}
	}
}
