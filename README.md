# LegacyOAuth
repository to support OAuth for applications, which are using .Net framework 3.0.

oAuth  is not supported below .net framework 4.5. I tried to create this library so that it be supported from .net framework 3.0 and above.

the steps to use this library is very simple. it is available in nuget.org.

download from there or copy below command in package manager console.

Install-Package Security.Authentication.SSO -Version 1.0.0

steps to use :

1. Add appsettings to web.config
<appSettings>
    <add key="SSO.LoginURI" value=""/>
    <add key="SSO.TokenURI" value=""/>
    <add key="SSO.ClientID" value=""/>
    <add key="SSO.ClientSecret" value=""/>
    <add key="SSO.TenantID" value=""/>
    <add key="SSO.Scope" value="User.Read"/>
    <add key="SSO.RedirectURI" value=""/>
  </appSettings>
  
  
 2.Add below lines to configuration:
 
 <system.webServer>
    <defaultDocument>
      <files>
        <add value="WebForm1.aspx" />
      </files>
    </defaultDocument>
    <directoryBrowse enabled="false" />
    <validation validateIntegratedModeConfiguration="false"/>
    <modules>
      <add name="SSOSecurity" type="SSOSecurity.SSOAuthenticationModule, SSOSecurity"/>
    </modules>
  </system.webServer>
