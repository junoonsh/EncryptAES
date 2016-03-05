<%@page import="encrypt.aes.AESEncryptAdapter" %>
<%@page session="true" %>
	
<%
String sessId;
try {
	AESEncryptAdapter login = new AESEncryptAdapter();
		sessId = login.login();
} catch (Exception e) {
	e.printStackTrace();
	return;
}
		session.setAttribute("p1", sessId);
		response.sendRedirect("mysso.jsp");
%>