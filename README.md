# Holyprin.Web.Security a Code-First Membership Provider #

This project is built using model abstraction and configuration in mind, it allows one to add the provider library to any project then write their user / role models inside that same project or any other that references the library. The provider uses reflection to instantiate the configured User/Role entities.

##Features

+ Model abstraction (models and contexts should be defined in external assemblies).
+ Highly configurable - providerUserKey can be of System.Int16, System.Int32, System.Int64, and System.Guid.
+ Includes a centralized configuration in App.config or Web.Config, no more declaring properties more then once!
+ Uses HMAC512 Hashing originally used in Altairis's membership provider.

##Notes
This is almost a complete rewrite of my [original](http://cfmembershipprovider.codeplex.com/) version.

I included feature requests like multiple key type support, and centralized configuration settings.

##Provider Configuration
```xml
<configuration>
	<!-- Section configuration, provider will not work without this at the top of the configuration section. -->
	<configSections>
		<section name="CFMembershipSettings" type="Holyprin.Web.Security.Configuration.CFMembershipSettings, Holyprin.Web.Security" />
	</configSections>

	<!-- Configuration settings for the provider, ALL settings are required. -->
	<CFMembershipSettings
		dbContext="Holyprin.Web.Security.MVC3.MembershipCode.MyBaseContext, Holyprin.Web.Security.MVC3"
		userObject="Holyprin.Web.Security.MVC3.Entities.User, Holyprin.Web.Security.MVC3"
		roleObject="Holyprin.Web.Security.MVC3.Entities.Role, Holyprin.Web.Security.MVC3"
		keyType="Guid" userTable="Users" roleTable="Roles" allowLoginWithEmail="true" useEmailAsUsername="false" />
	
	<connectionStrings>
		<!-- 2 Connection strings for Express / Standard, and Compact Edition -->
		<add name="Holyprin.Web.Security.Compact" connectionString="Data Source=|DataDirectory|Holyprin.Web.Security.sdf;Persist Security Info=False;" providerName="System.Data.SqlServerCe.4.0" />
		<add name="Holyprin.Web.Security.Express" connectionString="Data Source=.\SQLEXPRESS;AttachDbFilename=|DataDirectory|Holyprin.Web.Security.mdf;database=Holyprin.Web.Security;Integrated Security=True;User Instance=True" providerName="System.Data.SqlClient" />
	</connectionStrings>

	<system.web>
		<!-- Standard membership configuration here -->
		<membership defaultProvider="CFMembershipProvider">
			<providers>
				<clear/>
				<add applicationName="/" requiresQuestionAndAnswer="false"
				  requiresUniqueEmail="true" minRequiredNonalphanumericCharacters="0"
				  enablePasswordReset="true" connectionStringName="Holyprin.Web.Security.Express"
				  name="CFMembershipProvider" type="Holyprin.Web.Security.CFMembershipProvider, Holyprin.Web.Security" />
			</providers>
		</membership>

		<roleManager enabled="true" defaultProvider="CFRoleProvider">
			<providers>
				<clear/>
				<add name="AspNetWindowsTokenRoleProvider" type="System.Web.Security.WindowsTokenRoleProvider" applicationName="/" />
				<add name="CFRoleProvider" type="Holyprin.Web.Security.CFRoleProvider" connectionStringName="Holyprin.Web.Security.Express" applicationName="/" />
			</providers>
		</roleManager>

	</system.web>
</configuration>
```

Properties:
+ dbContext - "Namespace.To.Your.Data.Context, Assembly.Name.Without.Extension"
+ userObject - "Namespace.To.Your.User.Object, Assembly.Name.Without.Extension"
+ roleObject - "Namespace.To.Your.Role.Object, Assembly.Name.Without.Extension"
+ userTable - User table name in the database, this should match your object name, or your mapping in the DataContext.
+ roleTable - Role table name in the database, this should match your object name, or your mapping in the DataContext.
+ useEmailAsUsername - Configures the provider to replace the Username in the database with their email address !DO NOT CHANGE THIS SETTING ON EXISTING DATABASES!
+ allowLoginWithEmail - Configures the provider to always search for the users email or username to login.


##Model Configuration - Interface Implementation
```c#
public class Role : IProviderRole<User, Guid>
{
	[Key]
	[DatabaseGenerated(DatabaseGeneratedOption.Identity)] // Used for Microsoft SQL Server / SQL Server Express DO NOT USE WITH SQL Server Compact Edition
	public Guid RoleId { get; set; }
	public string Name { get; set; }
	public virtual ICollection<User> Users { get; set; }
}
```

OR

##Model Configuration - Abstract Class Implementation
```c#
public class Role : BaseRole<User, Guid>
{
	/*
	/	Base class only applies the Key attribute override and add DatabaseGenerated if needed.
	*/
	[Key]
	[DatabaseGenerated(DatabaseGeneratedOption.Identity)] // Used for Microsoft SQL Server / SQL Server Express DO NOT USE WITH SQL Server Compact Edition
	public override Guid RoleId { get; set; } 
}
```

To use IRole interface properly you would point User at YOUR User entity and Guid is what the Interface sets the key to be, this can be Int32/Int64/Int16/Guid. Make sure to change your implementation to correspond with the generic key type.

Please note that I, like Altairis, disagree with a few built in membership functions (GetPassword, Account lockdown, Clear/Encrypted Passwords) so I don't implement them. I will however make an exception for Account lockdown when I get around to building a netmask/IP Ban system for it.

##Special Thanks

+ Michal Altair Valášek (Altairis) - I used his configuration extension methods and modified his HMAC512 VerifyPassword() method.

If you like the project and want to support its development, help a girl out and [Donate](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=D64Y8TBGEAWBA). Anything is greatly appreciated and keeps me interested in the project.
