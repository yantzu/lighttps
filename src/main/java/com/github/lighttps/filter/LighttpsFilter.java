package com.github.lighttps.filter;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ReadListener;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.WriteListener;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LighttpsFilter implements Filter {
    
    private static final Logger LOG = LoggerFactory.getLogger(LighttpsFilter.class);
     
    private Handshaker handshaker;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        String certificateKeys = filterConfig.getInitParameter("CertificateKeys");
        if (certificateKeys == null || certificateKeys.isEmpty() || certificateKeys.trim().isEmpty()) {
            throw new IllegalArgumentException("Filter init-param 'CertificateKeys' cannot be null");
        }
        String ticketKeys = filterConfig.getInitParameter("TicketKeys");
        if (ticketKeys == null || ticketKeys.isEmpty() || ticketKeys.trim().isEmpty()) {
            throw new IllegalArgumentException("Filter init-param 'TicketKeys' cannot be null");
        }
        
        Map<String, PrivateKey> certificatePrivateKeys = initCertificateKeys(certificateKeys);
        Map<String, SecretKeySpec> ticketSecretKeys = initTicketKeys(ticketKeys);
        
        handshaker = new Handshaker(certificatePrivateKeys, ticketSecretKeys);
    }


    private Map<String, SecretKeySpec> initTicketKeys(String ticketKeys) {
        Map<String, SecretKeySpec> ticketSecretKeys = new HashMap<String, SecretKeySpec>();

        for (String ticketKey : ticketKeys.split(",")) {
            String[] ticketKeyParts = ticketKey.split("=");
            String ticketKeyVersion = ticketKeyParts[0];
            String ticketKeyData = ticketKeyParts[1];

            try {
                SecretKeySpec secretKeySpec = new SecretKeySpec(ticketKeyData.getBytes("UTF-8"), "AES");
                ticketSecretKeys.put(ticketKeyVersion, secretKeySpec);
            } catch (UnsupportedEncodingException unsupportedEncodingException) {
                throw new IllegalStateException(unsupportedEncodingException);
            }
        }

        return ticketSecretKeys;
    }

    

    private Map<String, PrivateKey> initCertificateKeys(String certificateKeys) {
        Map<String, PrivateKey> certificatePrivateKeys = new HashMap<String, PrivateKey>();
        
        PrivateKeyParser privateKeyParser = new PEMPrivateKeyParser();
        
        for (String certificateKey : certificateKeys.split(",")) {
            String[] certificateKeyParts = certificateKey.split("=");
            String certificateKeyVersion = certificateKeyParts[0];
            String[] certificateKeyFile = certificateKeyParts[1].split(":");
            String certificateKeyFileType = certificateKeyFile[0];
            String certificateKeyFilePath = certificateKeyFile[1];
            
            PrivateKey privateKey;
            if ("file".equals(certificateKeyFileType)) {
                try {
                    privateKey = privateKeyParser.parse(new FileInputStream(certificateKeyFilePath));
                } catch (FileNotFoundException fileNotFoundException) {
                    throw new IllegalArgumentException("File doesnot exist", fileNotFoundException);
                }
            } else if ("classpath".equals(certificateKeyFileType)) {
                privateKey = privateKeyParser.parse(this.getClass().getResourceAsStream(certificateKeyFilePath));
            } else {
                throw new IllegalArgumentException("Unknown Certificate Store Type:" + certificateKeyFileType);
            }
            certificatePrivateKeys.put(certificateKeyVersion, privateKey);
        }
        
        return certificatePrivateKeys;
    }
    

    @Override
    public void destroy() {
    }
    

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
            ServletException {
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResonpse = (HttpServletResponse) response;
        
        String rKey = null;
        try {
            rKey = handshaker.handshake(httpRequest, httpResonpse);
        } catch (KeyNotFoundException keyNotFoundException) {
            LOG.error("Unknown key version, check config immediately", keyNotFoundException);
            httpResonpse.sendError(495, keyNotFoundException.getMessage());
            return;
        } catch (InvalidKeyException invalidKeyException) {
            LOG.error("Failed to unwrap rKey, init new session", invalidKeyException);
            httpResonpse.sendError(495, invalidKeyException.getMessage());
            return;
        }
        
        if (rKey == null) {
            chain.doFilter(request, response);
            return;
        }
        
        HttpServletRequest httpRequestWrapper = httpRequest;
        HttpServletResponse httpResonpseWrapper = httpResonpse;
        
        try {
            if ("POST".equalsIgnoreCase(httpRequest.getMethod())
                    || "PUT".equalsIgnoreCase(httpRequest.getMethod())
                    || "PATCH".equalsIgnoreCase(httpRequest.getMethod())) {

                httpRequestWrapper = wrapInputStream(httpRequestWrapper, getDecryptCipher(rKey));
            }

            String ef = httpRequest.getParameter("ef");
            if (ef != null && !ef.isEmpty()) {
                httpRequestWrapper = wrapFile(httpRequestWrapper, ef, getDecryptCipher(rKey));
            }

            httpResonpseWrapper = wrapOutputStream(httpResonpseWrapper, getEncryptCipher(rKey));
        } catch (InvalidKeyException invalidKeyException) {
            LOG.error("Failed to init cipher, init new session", invalidKeyException);
            httpResonpse.sendError(495, invalidKeyException.getMessage());
            return;
        }
        
        
        chain.doFilter(httpRequestWrapper, httpResonpseWrapper);

        //close OutputStream to force flush data
        httpResonpseWrapper.getOutputStream().close();
        
        return;
    }


    private HttpServletResponse wrapOutputStream(HttpServletResponse httpResonpse, final Cipher encryptCipher)
            throws IOException {
        HttpServletResponse httpResonpseWrapper;
        final ServletOutputStream servletOutputStream = httpResonpse.getOutputStream();
        final CipherOutputStream cipherOutputStream = new CipherOutputStream(servletOutputStream, encryptCipher);
        final ServletOutputStream servletOutputStreamWrapper = new ServletOutputStream() {
            @Override
            public boolean isReady() {
                return servletOutputStream.isReady();
            }

            @Override
            public void setWriteListener(WriteListener writeListener) {
                servletOutputStream.setWriteListener(writeListener);
            }

            @Override
            public void write(int b) throws IOException {
                cipherOutputStream.write(b);
            }
            
            @Override
            public void close() throws IOException
            {
                cipherOutputStream.close();
            }
            
            @Override
            public void flush() throws IOException
            {
                cipherOutputStream.flush();
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException
            {
                cipherOutputStream.write(b, off, len);
            }

            @Override
            public void write(byte[] b) throws IOException
            {
                cipherOutputStream.write(b);
            }

            @Override
            public void print(String s) throws IOException
            {
                write(s.getBytes());
            }
        };
        httpResonpseWrapper = new HttpServletResponseWrapper(httpResonpse) {
            public ServletOutputStream getOutputStream() throws IOException {
                return servletOutputStreamWrapper;
            }
        };
        return httpResonpseWrapper;
    }


    private HttpServletRequest wrapFile(HttpServletRequest httpRequestWrapper, String ef, final Cipher decryptCipher)
            throws UnsupportedEncodingException, ServletException {
        try {
            final String uriString = decryptData(decryptCipher, ef);
            
            LOG.debug("Original request URI: {}", uriString);
            
            final URI uri = new URI(uriString);
            final Map<String, String[]> parameterMap = parseQuery(uri.getQuery());
            
            httpRequestWrapper = new HttpServletRequestWrapper(httpRequestWrapper) {
                @Override
                public String getQueryString() {
                    return uri.getQuery();
                }

                @Override
                public String getRequestURI() {
                    return uri.getPath();
                }

                @Override
                public String getServletPath() {
                    return uri.getPath();
                }

                @Override
                public String getParameter(String name) {
                    String[] values = parameterMap.get(name);
                    if (values != null && values.length > 0) {
                        return values[0];
                    } else {
                        return null;
                    }
                }

                @Override
                public Enumeration<String> getParameterNames() {
                    return Collections.enumeration(parameterMap.keySet());
                }

                @Override
                public String[] getParameterValues(String name) {
                    return parameterMap.get(name);
                }

                @Override
                public Map<String, String[]> getParameterMap() {
                    return parameterMap;
                }

                @Override
                public StringBuffer getRequestURL() {
                    StringBuffer sb = new StringBuffer();
                    sb.append(getRequest().getScheme()).append("://");
                    sb.append(getRequest().getLocalAddr()).append(":").append(getRequest().getLocalPort());
                    sb.append(uriString);
                    return sb;
                }
            };
        } catch (URISyntaxException uriSyntaxException) {
            throw new ServletException(uriSyntaxException);
        }
        return httpRequestWrapper;
    }


    private HttpServletRequest wrapInputStream(HttpServletRequest httpRequest,
            final Cipher decryptCipher) throws IOException {
        HttpServletRequest httpRequestWrapper;
        final ServletInputStream servletInputStream = httpRequest.getInputStream();
        @SuppressWarnings("resource")
        final CipherInputStream cipherInputStream = new CipherInputStream(servletInputStream, decryptCipher);
        final ServletInputStream servletInputStreamWrapper = new ServletInputStream() {
            @Override
            public boolean isFinished() {
                return servletInputStream.isFinished();
            }

            @Override
            public boolean isReady() {
                return servletInputStream.isReady();
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                servletInputStream.setReadListener(readListener);
            }

            @Override
            public int read() throws IOException
            {
                return cipherInputStream.read();
            }
            
            @Override
            public int read(byte[] b, int off, int len) throws IOException
            {
                return cipherInputStream.read(b, off, len);
            }

            @Override
            public int available() throws IOException {
                return cipherInputStream.available();
            }
        };
        
        httpRequestWrapper = new HttpServletRequestWrapper(httpRequest) {
            public ServletInputStream getInputStream() throws IOException {
                return servletInputStreamWrapper;
            }
        };
        return httpRequestWrapper;
    }
    
    
    public static Map<String, String[]> parseQuery(String query) throws UnsupportedEncodingException {
        if (query == null || query.isEmpty()) {
            return new HashMap<String, String[]>(0);
        }
        Map<String, List<String>> parameterMap = new LinkedHashMap<String, List<String>>();
        String[] parameterPairs = query.split("&");
        for (String parameterPair : parameterPairs) {
            int equalIndex = parameterPair.indexOf("=");
            String key = equalIndex > 0 ? URLDecoder.decode(parameterPair.substring(0, equalIndex), "UTF-8")
                    : parameterPair;
            if (!parameterMap.containsKey(key)) {
                parameterMap.put(key, new LinkedList<String>());
            }
            String value = equalIndex > 0 && parameterPair.length() > equalIndex + 1 ? URLDecoder.decode(
                    parameterPair.substring(equalIndex + 1), "UTF-8") : "";
            parameterMap.get(key).add(value);
        }

        Map<String, String[]> result = new LinkedHashMap<String, String[]>();
        for (Entry<String, List<String>> parameterEntry : parameterMap.entrySet()) {
            int valueLength = parameterEntry.getValue().size();
            result.put(parameterEntry.getKey(), parameterEntry.getValue().toArray(new String[valueLength]));
        }
        return result;
    }
    
    
    private Cipher getEncryptCipher(String key) throws InvalidKeyException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
            return cipher;
        } catch (GeneralSecurityException securityExcepiton) {
            throw new InvalidKeyException(securityExcepiton);
        } catch (UnsupportedEncodingException encodingException) {
            throw new IllegalStateException(encodingException);
        }
    }
    
    
    private Cipher getDecryptCipher(String key) throws InvalidKeyException {
        try {
            SecretKeySpec secretKeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            return cipher;
        } catch (GeneralSecurityException securityExcepiton) {
            throw new InvalidKeyException(securityExcepiton);
        } catch (UnsupportedEncodingException encodingException) {
            throw new IllegalStateException(encodingException);
        }
    }
    
    private String decryptData(Cipher cipher, String data) {
        try {
            return new String(cipher.doFinal(Base64.decodeBase64(data)), "UTF-8");
        } catch (GeneralSecurityException securityExcepiton) {
            throw new IllegalStateException(securityExcepiton);
        } catch (UnsupportedEncodingException encodingException) {
            throw new IllegalStateException(encodingException);
        }
    }

}
