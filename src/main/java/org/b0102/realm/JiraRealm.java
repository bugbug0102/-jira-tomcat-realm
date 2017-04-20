package org.b0102.realm;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.codec.binary.Base64;

public class JiraRealm extends RealmBase 
{
	private static final Log log = LogFactory.getLog(JiraRealm.class);
	
	protected String jiraRole;
	protected String jiraGroup;
	protected String jiraUrl;
	
	private String password;
	
	public JiraRealm()
	{
		final TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() 
		{
			@Override
			public java.security.cert.X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			@Override
			public void checkClientTrusted(final X509Certificate[] certs, final String authType) {
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] certs, final String authType) {
			}
		} };

		/** Install the all-trusting trust manager **/
		SSLContext sc;
		try 
		{
			sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			
		} catch (final NoSuchAlgorithmException | KeyManagementException ex) 
		{
			throw new RuntimeException(ex);
		}
		
		HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

		/** Create all-trusting host name verifier **/
		final HostnameVerifier allHostsValid = new HostnameVerifier() 
		{
			@Override
			public boolean verify(final String hostname, final SSLSession session) {
				return true;
			}
		};

		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}
	
	private void closeMe(final Closeable closeable)
	{
		if(closeable!=null)
		{
			try 
			{
				closeable.close();
			} catch (final IOException e) 
			{
				/** Ignore **/
			}
		}
	}
	
	private String getContent(final HttpURLConnection conn) throws IOException
	{
		final StringBuilder sb = new StringBuilder();
		InputStreamReader isr = null;
		BufferedReader br = null;
		try
		{
			isr = new InputStreamReader(conn.getInputStream());
			br = new BufferedReader(isr);
			
			String line;
            while ((line = br.readLine()) != null) 
            {
                sb.append(line+"\n");
            }
			
		}finally
		{
			closeMe(br);
			closeMe(isr);
		}
		return sb.toString();
	}

	@Override
	public Principal authenticate(final String username, final String credentials) {
		this.password = credentials;
		
		URL obj;
		HttpURLConnection conn = null;
		try 
		{
			final String url = String.format(jiraUrl, username);
			obj = new URL(url);
			if(log.isDebugEnabled())
			{
				log.debug("Auth. with Jira:" + url);
			}
			conn = (HttpURLConnection) obj.openConnection();
			final String encoded = Base64.encodeBase64String((username+":"+credentials).getBytes());
			
			conn.setRequestMethod("GET");
			conn.setRequestProperty("Content-Type", "application/json");
			conn.setRequestProperty("Authorization", "Basic "+encoded);

			final int responseCode = conn.getResponseCode();
			if(responseCode == 200)
			{
				final String content = getContent(conn);
				if(content.contains(jiraGroup))
				{
					if(log.isDebugEnabled())
					{
						log.debug("Response OK");
					}
					
					return getPrincipal(username);
				}else
				{
					if(log.isDebugEnabled())
					{
						log.error(String.format("Unable to find group %s", jiraGroup));	
					}
				}
				
			}else
			{
				/** Unauthorized or other error codes **/
				log.error("Jira Response Code:" + responseCode);
			}
			
		} catch (final IOException ex) 
		{
			log.error(ex.getMessage());
		}finally
		{
			if(conn!=null)
			{
				conn.disconnect();
			}
		}
		return null;
	}
	
	public String getJiraRole() {
		return jiraRole;
	}

	public void setJiraRole(String jiraRole) {
		this.jiraRole = jiraRole;
	}

	public String getJiraGroup() {
		return jiraGroup;
	}

	public void setJiraGroup(String jiraGroup) {
		this.jiraGroup = jiraGroup;
	}

	public String getJiraUrl() {
		return jiraUrl;
	}

	public void setJiraUrl(String jiraUrl) {
		this.jiraUrl = jiraUrl;
	}

	@Override
	protected String getName() 
	{
		return this.getClass().getSimpleName();
	}

	@Override
	protected String getPassword(final String username) 
	{
		return password;
	}

	@Override
	protected Principal getPrincipal(final String username) 
	{
		final List<String> roles = new ArrayList<String>();
		roles.add(jiraRole);
		return new GenericPrincipal(username, password, roles);
	}

}