package com.github.lighttps.filter;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;

public class Handshaker {
	
	private String defaultTicketKey;
	private Map<String, PrivateKey> certificateKeys = new HashMap<String, PrivateKey>();
	private Map<String, SecretKeySpec> ticketKeys = new HashMap<String, SecretKeySpec>();
	
	
	public Handshaker(Map<String, PrivateKey> certificateKeys, Map<String, SecretKeySpec> ticketKeys) {
		this.certificateKeys = new HashMap<String, PrivateKey>(certificateKeys);
		this.ticketKeys = new HashMap<String, SecretKeySpec>(ticketKeys);
		
		List<String> ticketKeyVersions = new ArrayList<String>(this.ticketKeys.keySet());
		Collections.sort(ticketKeyVersions);
		defaultTicketKey = ticketKeyVersions.get(ticketKeyVersions.size() - 1);
	}
	
	/**
	 * handshake and return raw data secret key
	 * 
	 * @param request
	 * @param response
	 * @return Data Key
	 * @throws KeyNotFoundException 
	 */
	public String handshake(HttpServletRequest request, HttpServletResponse response) throws KeyNotFoundException {
		String aKey = request.getHeader("X-A-Key");
		if (aKey != null && !aKey.isEmpty() && !aKey.trim().isEmpty()) {
			String[] aKeyParts = aKey.split(":");
			String aKeyVersion = aKeyParts[0];
			String aKeyData = aKeyParts[1];

			return decryptTicketAsRawKey(aKeyVersion, aKeyData);
		}

		String sKey = request.getHeader("X-S-Key");
		if (sKey != null && !sKey.isEmpty() && !sKey.trim().isEmpty()) {
			String[] sKeyParts = sKey.split(":");
			String sKeyVersion = sKeyParts[0];
			String sKeyData = sKeyParts[1];

			String rKey = decryptClientKeyAsRawKey(sKeyVersion, sKeyData);

			aKey = encryptRawKeyAsTicket(rKey);
			response.setHeader("X-A-Key", defaultTicketKey + ":" + aKey);
			return rKey;
		}

		return null;
	}
	
	
	private String decryptClientKeyAsRawKey(String certificateVersion, String clientKey) throws KeyNotFoundException {
		PrivateKey certificateKey = certificateKeys.get(certificateVersion);
		if (certificateKey == null) {
			throw new KeyNotFoundException("Unknown CertificateKey: " + certificateVersion);
		}

		try {
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			cipher.init(Cipher.DECRYPT_MODE, certificateKey);
			return new String(cipher.doFinal(Base64.decodeBase64(clientKey)), "UTF-8");
		} catch (GeneralSecurityException securityExcepiton) {
			throw new IllegalStateException(securityExcepiton);
		} catch (UnsupportedEncodingException encodingException) {
			throw new IllegalStateException(encodingException);
		}
	}
	
	
	private String encryptRawKeyAsTicket(String rawKey) {
		SecretKeySpec ticketKey = ticketKeys.get(defaultTicketKey);

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
			cipher.init(Cipher.ENCRYPT_MODE, ticketKey);
			return Base64.encodeBase64String(cipher.doFinal(rawKey.getBytes()));
		} catch (GeneralSecurityException securityExcepiton) {
			throw new IllegalStateException(securityExcepiton);
		}
	}
	
	private String decryptTicketAsRawKey(String ticketVersion, String encryptTicketData) throws KeyNotFoundException {
		SecretKeySpec ticketKey = ticketKeys.get(ticketVersion);
		if (ticketKey == null) {
			throw new KeyNotFoundException("Unknown TicketKey: "
					+ ticketVersion);
		}

		try {
			Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
			cipher.init(Cipher.DECRYPT_MODE, ticketKey);
			return new String(cipher.doFinal(Base64.decodeBase64(encryptTicketData)), "UTF-8");
		} catch (GeneralSecurityException securityExcepiton) {
			throw new IllegalStateException(securityExcepiton);
		} catch (UnsupportedEncodingException encodingException) {
			throw new IllegalStateException(encodingException);
		}
	}
	
}
