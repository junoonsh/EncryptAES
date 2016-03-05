<%@page import="encrypt.aes.AESEncryptAdapter" %>
<form method="post" name="login" action="https://<%=encrypt.aes.AESEncryptAdapter.sURL%>.mypay.com/loginconfirm.asp?instid=<%=encrypt.aes.AESEncryptAdapter.nInstitutionID%>&op=Login&Method=Session&CompanyID=<%=encrypt.aes.AESEncryptAdapter.sCompanyID%>">
  <input type="hidden" name="p1" value="<%=session.getAttribute("p1") %>"/>
</form>
<script>
	document.login.submit();
</script>
