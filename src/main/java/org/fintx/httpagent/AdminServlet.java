package org.fintx.httpagent;

import javax.servlet.annotation.WebInitParam;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;

@WebServlet(displayName = "AdminServlet" , //描述  
name = "AdminServlet", //servlet名称  
urlPatterns = { "/admin","/admin" }, //url  
loadOnStartup = 1, //启动项  
initParams = { @WebInitParam(name = "username", value = "张三") }  )
public class AdminServlet extends HttpServlet {

    /**
     * 
     */
    private static final long serialVersionUID = -8762294920980583988L;

}
