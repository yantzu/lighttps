package com.github.yantzu.lighttps;

import java.io.IOException;
import java.io.InputStream;
import java.util.Scanner;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Assert;

public class DispatcherServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		Assert.assertEquals("/targetUrl", req.getRequestURI());
		Assert.assertEquals("targetP=targetV", req.getQueryString());
		Assert.assertEquals("targetV", req.getParameter("targetP"));
		Assert.assertEquals(1, req.getParameterMap().size());
		
		resp.getOutputStream().write("resultX".getBytes());
		resp.getOutputStream().flush();
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		Assert.assertEquals("/targetUrl", req.getRequestURI());
		Assert.assertEquals("targetP=targetV", req.getQueryString());
		Assert.assertEquals("targetV", req.getParameter("targetP"));
		Assert.assertEquals(1, req.getParameterMap().size());
		
		String content = toString(req.getInputStream());
		Assert.assertEquals("contentX", content);
		
		
		resp.getOutputStream().write("resultX".getBytes());
		resp.getOutputStream().flush();
	}
	
	private String toString(InputStream inputStream) {
		Scanner scanner = new Scanner(inputStream);
		scanner.useDelimiter("\\A");
		try {
			return scanner.hasNext() ? scanner.next() : "";
		} finally {
			scanner.close();
		}
	}
}
