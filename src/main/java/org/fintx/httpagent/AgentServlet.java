package org.fintx.httpagent;

import org.apache.http.Consts;

/**
 * Copyright MITRE
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CookieStore;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.AuthSchemes;
import org.apache.http.client.config.CookieSpecs;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.concurrent.FutureCallback;
import org.apache.http.config.ConnectionConfig;
import org.apache.http.config.MessageConstraints;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.DnsResolver;
import org.apache.http.conn.routing.HttpRoute;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.impl.DefaultHttpResponseFactory;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.conn.SystemDefaultDnsResolver;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.apache.http.impl.nio.codecs.DefaultHttpRequestWriterFactory;
import org.apache.http.impl.nio.codecs.DefaultHttpResponseParserFactory;
import org.apache.http.impl.nio.codecs.DefaultHttpResponseParser;
import org.apache.http.impl.nio.conn.ManagedNHttpClientConnectionFactory;
import org.apache.http.impl.nio.conn.PoolingNHttpClientConnectionManager;
import org.apache.http.impl.nio.reactor.DefaultConnectingIOReactor;
import org.apache.http.impl.nio.reactor.IOReactorConfig;
import org.apache.http.message.BasicHeader;
import org.apache.http.message.BasicHttpEntityEnclosingRequest;
import org.apache.http.message.BasicHttpRequest;
import org.apache.http.message.BasicLineParser;
import org.apache.http.message.HeaderGroup;
import org.apache.http.message.LineParser;
import org.apache.http.nio.NHttpMessageParser;
import org.apache.http.nio.NHttpMessageParserFactory;
import org.apache.http.nio.NHttpMessageWriterFactory;
import org.apache.http.nio.client.HttpAsyncClient;
import org.apache.http.nio.conn.ManagedNHttpClientConnection;
import org.apache.http.nio.conn.NHttpConnectionFactory;
import org.apache.http.nio.conn.NoopIOSessionStrategy;
import org.apache.http.nio.conn.SchemeIOSessionStrategy;
import org.apache.http.nio.conn.ssl.SSLIOSessionStrategy;
import org.apache.http.nio.reactor.ConnectingIOReactor;
import org.apache.http.nio.reactor.SessionInputBuffer;
import org.apache.http.nio.util.HeapByteBufferAllocator;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.TrustStrategy;
import org.apache.http.util.CharArrayBuffer;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.servlet.AsyncContext;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Closeable;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.CodingErrorAction;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.BitSet;
import java.util.Enumeration;
import java.util.Formatter;
import java.util.List;


@WebServlet(name = "AgentServlet",
        urlPatterns = { "/agent" },
        loadOnStartup = 1,
        initParams = { @WebInitParam(name = "username", value = "张三"), @WebInitParam(name = "proxyUri", value = "http://1.2.3.4:8080") })
public class AgentServlet extends HttpServlet {

    /* INIT PARAMETER NAME CONSTANTS */

    /**
     * 
     */
    private static final long serialVersionUID = 2816066535269412300L;

    /** The parameter name for the target (destination) URL to proxy to. */
    protected static final String TARGET_URL = "targetUrl";

    protected static final String TARGET_HOST = "targetHost";
    protected static final String PROXY_URI = "proxyUri";
    private HttpAsyncClient httpClient;
    private HttpAsyncClient httpsClient;

    protected String getTargetUrl(HttpServletRequest servletRequest) {
        return (String) servletRequest.getParameter(TARGET_URL);
    }

    private HttpHost getTargetHost(HttpServletRequest servletRequest) {
        return (HttpHost) servletRequest.getAttribute(TARGET_HOST);
    }

    /**
     * Reads a configuration parameter. By default it reads servlet init parameters but it can be overridden.
     */
    protected String getConfigParam(String key) {
        return getServletConfig().getInitParameter(key);
    }

    protected Boolean getBoolConfigParam(String key) {
        String s = getConfigParam(key);
        if (s != null) {
            return Boolean.parseBoolean(s);
        }
        return false;
    }

    @Override
    public void init() throws ServletException {
        httpClient = createAsyncHttpClient();
    }

    protected HttpAsyncClient createAsyncHttpClient() {
        try {
            RequestConfig requestConfig =
                    RequestConfig.custom().setSocketTimeout(10000).setConnectTimeout(10000).setCookieSpec(CookieSpecs.IGNORE_COOKIES)
                            .setExpectContinueEnabled(true).setTargetPreferredAuthSchemes(Arrays.asList(AuthSchemes.NTLM, AuthSchemes.DIGEST))
                            .setProxyPreferredAuthSchemes(Arrays.asList(AuthSchemes.BASIC)).build();

            // Use custom message parser / writer to customize the way HTTP
            // messages are parsed from and written out to the data stream.
            NHttpMessageParserFactory<HttpResponse> responseParserFactory = new DefaultHttpResponseParserFactory() {
                @Override
                public NHttpMessageParser<HttpResponse> create(final SessionInputBuffer buffer, final MessageConstraints constraints) {
                    LineParser lineParser = new BasicLineParser() {

                        @Override
                        public Header parseHeader(final CharArrayBuffer buffer) {
                            try {
                                return super.parseHeader(buffer);
                            } catch (ParseException ex) {
                                return new BasicHeader(buffer.toString(), null);
                            }
                        }

                    };
                    return new DefaultHttpResponseParser(buffer, lineParser, DefaultHttpResponseFactory.INSTANCE, constraints);
                }

            };
            NHttpMessageWriterFactory<HttpRequest> requestWriterFactory = new DefaultHttpRequestWriterFactory();

            // Use a custom connection factory to customize the process of
            // initialization of outgoing HTTP connections. Beside standard connection
            // configuration parameters HTTP connection factory can define message
            // parser / writer routines to be employed by individual connections.
            NHttpConnectionFactory<ManagedNHttpClientConnection> connFactory =
                    new ManagedNHttpClientConnectionFactory(requestWriterFactory, responseParserFactory, HeapByteBufferAllocator.INSTANCE);

            // 全部信任 不做身份鉴定
            SSLContext sslContext = new SSLContextBuilder().loadTrustMaterial(null, new TrustStrategy() {
                public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
                    return true;
                }
            }).build();//.loadKeyMaterial(keystore, keyPassword).build();
            // 支持全部加密算法-SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.2"
            SSLIOSessionStrategy sslSessionStrategy = new SSLIOSessionStrategy(sslContext, new String[] { "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.2" },
                    null, SSLIOSessionStrategy.getDefaultHostnameVerifier());

            // Create a registry of custom connection session strategies for supported
            // protocol schemes.
            Registry<SchemeIOSessionStrategy> sessionStrategyRegistry = RegistryBuilder.<SchemeIOSessionStrategy> create()
                    .register("http", NoopIOSessionStrategy.INSTANCE).register("https", sslSessionStrategy).build();

            // Use custom DNS resolver to override the system DNS resolution.
            DnsResolver dnsResolver = new SystemDefaultDnsResolver() {

                @Override
                public InetAddress[] resolve(final String host) throws UnknownHostException {
                    if (host.equalsIgnoreCase("myhost")) {
                        return new InetAddress[] { InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }) };
                    } else {
                        return super.resolve(host);
                    }
                }

            };

            // Create I/O reactor configuration
            IOReactorConfig ioReactorConfig = IOReactorConfig.custom().setIoThreadCount(Runtime.getRuntime().availableProcessors())
                    .setConnectTimeout(30000).setSoTimeout(30000).build();

            // Create a custom I/O reactort
            ConnectingIOReactor ioReactor = new DefaultConnectingIOReactor(ioReactorConfig);
            // Create a connection manager with custom configuration.
            PoolingNHttpClientConnectionManager connManager =
                    new PoolingNHttpClientConnectionManager(ioReactor, connFactory, sessionStrategyRegistry, dnsResolver);
            // Create message constraints
            MessageConstraints messageConstraints = MessageConstraints.custom().setMaxHeaderCount(200).setMaxLineLength(2000).build();
            // Create connection configuration
            ConnectionConfig connectionConfig = ConnectionConfig.custom().setMalformedInputAction(CodingErrorAction.IGNORE)
                    .setUnmappableInputAction(CodingErrorAction.IGNORE).setCharset(Consts.UTF_8).setMessageConstraints(messageConstraints).build();
            // Configure the connection manager to use connection configuration either
            // by default or for a specific host.
            connManager.setDefaultConnectionConfig(connectionConfig);
            connManager.setConnectionConfig(new HttpHost("somehost", 80), ConnectionConfig.DEFAULT);

            // Configure total max or per route limits for persistent connections
            // that can be kept in the pool or leased by the connection manager.
            connManager.setMaxTotal(100);
            connManager.setDefaultMaxPerRoute(10);
            connManager.setMaxPerRoute(new HttpRoute(new HttpHost("somehost", 80)), 20);

            // Use custom cookie store if necessary.
            CookieStore cookieStore = new BasicCookieStore();
            // Use custom credentials provider if necessary.
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            credentialsProvider.setCredentials(new AuthScope("localhost", 8889), new UsernamePasswordCredentials("squid", "nopassword"));

            HttpHost proxy = null;
            if (null != getConfigParam(PROXY_URI)) {
                proxy = HttpHost.create(getConfigParam(PROXY_URI));
            }

            CloseableHttpAsyncClient res = HttpAsyncClients.custom().setDefaultRequestConfig(requestConfig).setConnectionManager(connManager)
                    .setDefaultCookieStore(cookieStore).setDefaultCredentialsProvider(credentialsProvider).setProxy(proxy).build();
            res.start();
            return res;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected HttpAsyncClient getProxyClientAsync() {
        return httpClient;
    }

    @Override
    public void destroy() {
        if (httpClient instanceof CloseableHttpAsyncClient) {
            try {
                ((CloseableHttpAsyncClient) httpClient).close();
            } catch (IOException e) {
                log("While destroying servlet, shutting down HttpAsyncClient: " + e, e);
            }
        }
        super.destroy();
    }

    @Override
    protected void service(final HttpServletRequest servletRequest, final HttpServletResponse servletResponse) throws ServletException, IOException {

        // initialize request attributes from caches if unset by a subclass by this point
        if (null == servletRequest.getParameter(TARGET_URL) || "".equals(servletRequest.getParameter(TARGET_URL).trim())) {
            servletResponse.sendError(500, "No target url defined!");
            return;
        }
        URL targetUrl = null;
        try {
            targetUrl = new URL(servletRequest.getParameter(TARGET_URL));
        } catch (MalformedURLException e) {
            servletResponse.sendError(500, e.getMessage());
            return;
        }
        HttpHost targetHost = null;
        try {
            targetHost = URIUtils.extractHost(targetUrl.toURI());
        } catch (URISyntaxException e) {
            servletResponse.sendError(500, e.getMessage());
            return;
        }
        servletRequest.setAttribute(TARGET_HOST, targetHost);

        if (!"ftp".equals(targetUrl.getProtocol()) && !"http".equals(targetUrl.getProtocol()) && !"https".equals(targetUrl.getProtocol())) {
            servletResponse.sendError(416, "Not supported protocol in target url!");
            return;
        }
        if ("ftp".equals(targetUrl.getProtocol())) {

        } else if ("http".equals(targetUrl.getProtocol()) && !"https".equals(targetUrl.getProtocol())) {
            // Make the Request
            // note: we won't transfer the protocol version because I'm not sure it would truly be compatible
            String method = servletRequest.getMethod();
            String proxyRequestUrl = getTargetUrl(servletRequest);
            HttpRequest proxyRequest;
            // spec: RFC 2616, sec 4.3: either of these two headers signal that there is a message body.
            if (servletRequest.getHeader(HttpHeaders.CONTENT_LENGTH) != null || servletRequest.getHeader(HttpHeaders.TRANSFER_ENCODING) != null) {
                HttpEntityEnclosingRequest eProxyRequest = new BasicHttpEntityEnclosingRequest(method, proxyRequestUrl);
                // Add the input entity (streamed)
                // note: we don't bother ensuring we close the servletInputStream since the container handles it
                eProxyRequest.setEntity(new InputStreamEntity(servletRequest.getInputStream(), servletRequest.getContentLength()));
                proxyRequest = eProxyRequest;
            } else {
                proxyRequest = new BasicHttpRequest(method, proxyRequestUrl);
            }

            copyRequestHeaders(servletRequest, proxyRequest);

            setXForwardedForHeader(servletRequest, proxyRequest);

            // if (doLog) {
            // log("proxy " + method + " uri: " + servletRequest.getRequestURI() + " -- " +
            // proxyRequest.getRequestLine().getUri());
            // }
            // Async, non-blocking proxy
            // -------------------------
            serviceAsync(proxyRequest, servletRequest, servletResponse);
        }

    }

    protected void serviceAsync(final HttpRequest proxyRequest, final HttpServletRequest servletRequest, final HttpServletResponse servletResponse) {
        final AsyncContext asyncContext = servletRequest.startAsync();
        getProxyClientAsync().execute(getTargetHost(servletRequest), proxyRequest, new FutureCallback<HttpResponse>() {

            public void completed(HttpResponse httpResponse) {
                log("Response received from target : " + httpResponse.getStatusLine());
                // Process the response
                try {
                    handleResponse(httpResponse, servletRequest, servletResponse);
                    asyncContext.complete();
                } catch (Exception e) {
                    failed(e);
                }
            }

            public void failed(Exception e) {
                try {
                    log("Error while contacting target host", e);
                    servletResponse.sendError(500, e.getMessage());
                } catch (Exception e2) {
                    log("Error sending error", e2);
                } finally {
                    asyncContext.complete();
                }
            }

            public void cancelled() {

                try {
                    log("Cancelled");
                    servletResponse.sendError(500, " Request Cancelled");
                } catch (Exception e2) {
                    log("Error sending error", e2);
                } finally {
                    asyncContext.complete();
                }
            }
        });
    }

    protected void handleResponse(HttpResponse proxyResponse, HttpServletRequest servletRequest, HttpServletResponse servletResponse)
            throws ServletException, IOException {

        int statusCode = proxyResponse.getStatusLine().getStatusCode();

        if (doResponseRedirectOrNotModifiedLogic(servletRequest, servletResponse, proxyResponse, statusCode)) {
            // the response is already "committed" now without any body to send
            // TODO copy response headers?
            servletResponse.setStatus(statusCode);
            return;
        }

        // Pass the response code. This method with the "reason phrase" is deprecated but it's the only way to pass the
        // reason along too.
        // noinspection deprecation
        servletResponse.sendError(statusCode, proxyResponse.getStatusLine().getReasonPhrase());

        copyResponseHeaders(proxyResponse, servletRequest, servletResponse);

        // Send the content to the client
        copyResponseEntity(proxyResponse, servletResponse);
    }

    protected boolean doResponseRedirectOrNotModifiedLogic(HttpServletRequest servletRequest, HttpServletResponse servletResponse,
            HttpResponse proxyResponse, int statusCode) throws ServletException, IOException {
        // Check if the proxy response is a redirect
        // The following code is adapted from org.tigris.noodle.filters.CheckForRedirect
        if (statusCode >= HttpServletResponse.SC_MULTIPLE_CHOICES /* 300 */
                && statusCode < HttpServletResponse.SC_NOT_MODIFIED /* 304 */) {
            Header locationHeader = proxyResponse.getLastHeader(HttpHeaders.LOCATION);
            if (locationHeader == null) {
                throw new ServletException(
                        "Received status code: " + statusCode + " but no " + HttpHeaders.LOCATION + " header was found in the response");
            }
            // Modify the redirect to go to this proxy servlet rather that the proxied host
            String locStr = rewriteUrlFromResponse(servletRequest, locationHeader.getValue());

            servletResponse.sendRedirect(locStr);
            return true;
        }
        // 304 needs special handling. See:
        // http://www.ics.uci.edu/pub/ietf/http/rfc1945.html#Code304
        // We get a 304 whenever passed an 'If-Modified-Since'
        // header and the data on disk has not changed; server
        // responds w/ a 304 saying I'm not going to send the
        // body because the file has not changed.
        if (statusCode == HttpServletResponse.SC_NOT_MODIFIED) {
            servletResponse.setIntHeader(HttpHeaders.CONTENT_LENGTH, 0);
            servletResponse.setStatus(HttpServletResponse.SC_NOT_MODIFIED);
            return true;
        }
        return false;
    }

    protected void closeQuietly(Closeable closeable) {
        try {
            closeable.close();
        } catch (IOException e) {
            log(e.getMessage(), e);
        }
    }

    /**
     * HttpClient v4.1 doesn't have the
     * {@link org.apache.http.util.EntityUtils#consumeQuietly(org.apache.http.HttpEntity)} method.
     */
    protected void consumeQuietly(HttpEntity entity) {
        try {
            EntityUtils.consume(entity);
        } catch (IOException e) {// ignore
            log(e.getMessage(), e);
        }
    }

    /**
     * These are the "hop-by-hop" headers that should not be copied.
     * http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html I use an HttpClient HeaderGroup class instead of Set
     * <String> because this approach does case insensitive lookup faster.
     */
    protected static final HeaderGroup hopByHopHeaders;
    static {
        hopByHopHeaders = new HeaderGroup();
        String[] headers = new String[] { "Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailers",
                "Transfer-Encoding", "Upgrade" };
        for (String header : headers) {
            hopByHopHeaders.addHeader(new BasicHeader(header, null));
        }
    }

    /** Copy request headers from the servlet client to the proxy request. */
    protected void copyRequestHeaders(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
        // Get an Enumeration of all of the header names sent by the client
        Enumeration enumerationOfHeaderNames = servletRequest.getHeaderNames();
        while (enumerationOfHeaderNames.hasMoreElements()) {
            String headerName = (String) enumerationOfHeaderNames.nextElement();
            // Instead the content-length is effectively set via InputStreamEntity
            if (headerName.equalsIgnoreCase(HttpHeaders.CONTENT_LENGTH))
                continue;
            if (hopByHopHeaders.containsHeader(headerName))
                continue;

            Enumeration headers = servletRequest.getHeaders(headerName);
            while (headers.hasMoreElements()) {// sometimes more than one value
                String headerValue = (String) headers.nextElement();
                // In case the proxy host is running multiple virtual servers,
                // rewrite the Host header to ensure that we get content from
                // the correct virtual server
                if (headerName.equalsIgnoreCase(HttpHeaders.HOST)) {
                    HttpHost host = getTargetHost(servletRequest);
                    headerValue = host.getHostName();
                    if (host.getPort() != -1)
                        headerValue += ":" + host.getPort();
                } else if (headerName.equalsIgnoreCase(org.apache.http.cookie.SM.COOKIE)) {
                    headerValue = getRealCookie(headerValue);
                }
                proxyRequest.addHeader(headerName, headerValue);
            }
        }
    }

    private void setXForwardedForHeader(HttpServletRequest servletRequest, HttpRequest proxyRequest) {
        String headerName = "X-Forwarded-For";
        String newHeader = servletRequest.getRemoteAddr();
        String existingHeader = servletRequest.getHeader(headerName);
        if (existingHeader != null) {
            newHeader = existingHeader + ", " + newHeader;
        }
        proxyRequest.setHeader(headerName, newHeader);
    }

    /** Copy proxied response headers back to the servlet client. */
    protected void copyResponseHeaders(HttpResponse proxyResponse, HttpServletRequest servletRequest, HttpServletResponse servletResponse) {
        for (Header header : proxyResponse.getAllHeaders()) {
            if (hopByHopHeaders.containsHeader(header.getName()))
                continue;
            if (header.getName().equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE)
                    || header.getName().equalsIgnoreCase(org.apache.http.cookie.SM.SET_COOKIE2)) {
                copyProxyCookie(servletRequest, servletResponse, header);
            } else {
                servletResponse.addHeader(header.getName(), header.getValue());
            }
        }
    }

    /**
     * Copy cookie from the proxy to the servlet client. Replaces cookie path to local path and renames cookie to avoid
     * collisions.
     */
    protected void copyProxyCookie(HttpServletRequest servletRequest, HttpServletResponse servletResponse, Header header) {
        List<HttpCookie> cookies = HttpCookie.parse(header.getValue());
        String path = servletRequest.getContextPath(); // path starts with / or is empty string
        path += servletRequest.getServletPath(); // servlet path starts with / or is empty string

        for (HttpCookie cookie : cookies) {
            // set cookie name prefixed w/ a proxy value so it won't collide w/ other cookies
            String proxyCookieName = getCookieNamePrefix() + cookie.getName();
            Cookie servletCookie = new Cookie(proxyCookieName, cookie.getValue());
            servletCookie.setComment(cookie.getComment());
            servletCookie.setMaxAge((int) cookie.getMaxAge());
            servletCookie.setPath(path); // set to the path of the proxy servlet
            // don't set cookie domain
            servletCookie.setSecure(cookie.getSecure());
            servletCookie.setVersion(cookie.getVersion());
            servletResponse.addCookie(servletCookie);
        }
    }

    /**
     * Take any client cookies that were originally from the proxy and prepare them to send to the proxy. This relies on
     * cookie headers being set correctly according to RFC 6265 Sec 5.4. This also blocks any local cookies from being
     * sent to the proxy.
     */
    protected String getRealCookie(String cookieValue) {
        StringBuilder escapedCookie = new StringBuilder();
        String cookies[] = cookieValue.split("; ");
        for (String cookie : cookies) {
            String cookieSplit[] = cookie.split("=");
            if (cookieSplit.length == 2) {
                String cookieName = cookieSplit[0];
                if (cookieName.startsWith(getCookieNamePrefix())) {
                    cookieName = cookieName.substring(getCookieNamePrefix().length());
                    if (escapedCookie.length() > 0) {
                        escapedCookie.append("; ");
                    }
                    escapedCookie.append(cookieName).append("=").append(cookieSplit[1]);
                }
            }

            cookieValue = escapedCookie.toString();
        }
        return cookieValue;
    }

    /** The string prefixing rewritten cookies. */
    protected String getCookieNamePrefix() {
        return "!Proxy!" + getServletConfig().getServletName();
    }

    /** Copy response body data (the entity) from the proxy to the servlet client. */
    protected void copyResponseEntity(HttpResponse proxyResponse, HttpServletResponse servletResponse) throws IOException {
        HttpEntity entity = proxyResponse.getEntity();
        if (entity != null) {
            OutputStream servletOutputStream = servletResponse.getOutputStream();
            entity.writeTo(servletOutputStream);
        }
    }

    // /**
    // * Reads the request URI from {@code servletRequest} and rewrites it, considering targetUri. It's used to make the
    // * new request.
    // */
    // protected String rewriteUrlFromRequest(HttpServletRequest servletRequest) {
    // StringBuilder url = new StringBuilder(512);
    // url.append(getTargetUrl(servletRequest));
    // // Handle the path given to the servlet
    // if (servletRequest.getPathInfo() != null) {// ex: /my/path.html
    // url.append(encodeUriQuery(servletRequest.getPathInfo()));
    // }
    // // Handle the query string & fragment
    // String queryString = servletRequest.getQueryString();// ex:(following '?'): name=value&foo=bar#fragment
    // String fragment = null;
    // // split off fragment from queryString, updating queryString if found
    // if (queryString != null) {
    // int fragIdx = queryString.indexOf('#');
    // if (fragIdx >= 0) {
    // fragment = queryString.substring(fragIdx + 1);
    // queryString = queryString.substring(0, fragIdx);
    // }
    // }
    //
    // queryString = rewriteQueryStringFromRequest(servletRequest, queryString);
    // if (queryString != null && queryString.length() > 0) {
    // url.append('?');
    // url.append(encodeUriQuery(queryString));
    // }
    // if (fragment != null) {
    // url.append('#');
    // url.append(encodeUriQuery(fragment));
    // }
    // return url.toString();
    // }

    protected String rewriteQueryStringFromRequest(HttpServletRequest servletRequest, String queryString) {
        return queryString;
    }

    /**
     * For a redirect response from the target server, this translates {@code theUrl} to redirect to and translates it
     * to one the original client can use.
     */
    protected String rewriteUrlFromResponse(HttpServletRequest servletRequest, String theUrl) {
        // TODO document example paths
        final String targetUrl = getTargetUrl(servletRequest);
        if (theUrl.startsWith(targetUrl)) {
            String curUrl = servletRequest.getRequestURL().toString();// no query
            String pathInfo = servletRequest.getPathInfo();
            if (pathInfo != null) {
                assert curUrl.endsWith(pathInfo);
                curUrl = curUrl.substring(0, curUrl.length() - pathInfo.length());// take pathInfo off
            }
            theUrl = curUrl + theUrl.substring(targetUrl.length());
        }
        return theUrl;
    }

    /**
     * Encodes characters in the query or fragment part of the URI.
     *
     * <p>
     * Unfortunately, an incoming URI sometimes has characters disallowed by the spec. HttpClient insists that the
     * outgoing proxied request has a valid URI because it uses Java's {@link URI}. To be more forgiving, we must escape
     * the problematic characters. See the URI class for the spec.
     *
     * @param in example: name=value&foo=bar#fragment
     */
    protected static CharSequence encodeUriQuery(CharSequence in) {
        // Note that I can't simply use URI.java to encode because it will escape pre-existing escaped things.
        StringBuilder outBuf = null;
        Formatter formatter = null;
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            boolean escape = true;
            if (c < 128) {
                if (asciiQueryChars.get((int) c)) {
                    escape = false;
                }
            } else if (!Character.isISOControl(c) && !Character.isSpaceChar(c)) {// not-ascii
                escape = false;
            }
            if (!escape) {
                if (outBuf != null)
                    outBuf.append(c);
            } else {
                // escape
                if (outBuf == null) {
                    outBuf = new StringBuilder(in.length() + 5 * 3);
                    outBuf.append(in, 0, i);
                    formatter = new Formatter(outBuf);
                }
                // leading %, 0 padded, width 2, capital hex
                formatter.format("%%%02X", (int) c);// TODO
            }
        }
        return outBuf != null ? outBuf : in;
    }

    protected static final BitSet asciiQueryChars;
    static {
        char[] c_unreserved = "_-!.~'()*".toCharArray();// plus alphanum
        char[] c_punct = ",;:$&+=".toCharArray();
        char[] c_reserved = "?/[]@".toCharArray();// plus punct

        asciiQueryChars = new BitSet(128);
        for (char c = 'a'; c <= 'z'; c++)
            asciiQueryChars.set((int) c);
        for (char c = 'A'; c <= 'Z'; c++)
            asciiQueryChars.set((int) c);
        for (char c = '0'; c <= '9'; c++)
            asciiQueryChars.set((int) c);
        for (char c : c_unreserved)
            asciiQueryChars.set((int) c);
        for (char c : c_punct)
            asciiQueryChars.set((int) c);
        for (char c : c_reserved)
            asciiQueryChars.set((int) c);

        asciiQueryChars.set((int) '%');// leave existing percent escapes in place
    }

}
