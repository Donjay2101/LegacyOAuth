using System;
using System.Security.Principal;

namespace SSOSecurity
{
	/// <summary>
	/// Represents the Identity of a User. 
	/// Stores the details of a User. 
	/// Implements the IIDentity interface.
	/// </summary>
	[Serializable]
	public class SSOIdentity : IIdentity
	{
		#region private variables

		//internal string _userId;
		//internal  int _userPK;
		//internal bool _login;
		//internal bool _isSuperUser;
		//internal string _fullName;
		//internal string _email;
		//internal string _roles;
		//internal string _givenName;
		//internal string _familyName;

		#endregion

		# region constructors
		/// <summary>
		/// The default constructor initializes any fields to their default values.
		/// </summary>
		public SSOIdentity()
		{
			UserPK				= 0;
			UserName			= String.Empty;
			IsAuthenticated				= false;
			IsSuperUser			= false;
			UserFullName		= String.Empty;
			UserEmail			= String.Empty;
			UserRoles			= String.Empty;
		}

		/// <summary>
		/// Initializes a new instance of the SSOIdentity class 
		/// with the passed parameters
		/// </summary>
		/// <param name="uId">User ID of the user</param>
		/// <param name="upk">Primary Key of the User record in User table</param>
		/// <param name="islogin">Flag that indicates whether the user has been authenticated</param>
		/// <param name="isAdmin">Flag that indicates whether the user is an Administrator</param>
		/// <param name="userName">Full name of the User</param>
		/// <param name="email">Email of the User</param>
		public SSOIdentity(string uId, int upk, bool islogin, bool isAdmin, string userName, string email, string uRoles)
		{
			UserPK			= upk;
			UserName		= uId;
			IsAuthenticated = islogin;
			IsSuperUser		= isAdmin;
			UserFullName	= userName;
			UserEmail		= email;
			UserRoles		= uRoles;
		}

		#endregion

		# region properties
		// Properties
		/// <summary>
		/// Gets the Authentication Type
		/// </summary>
		public string AuthenticationType 
		{
			get { return "SSO"; }
		}

		/// <summary>
		/// Indicates whether the User is authenticated
		/// </summary>
		public bool IsAuthenticated  
		{
			get;set;
		}

		/// <summary>
		/// Gets or sets the UserID of the User
		/// </summary>
		public string UserName 
		{
			get; set;
		}

		/// <summary>
		/// Gets or sets the Primary Key for the User record
		/// </summary>
		public int UserPK 
		{
			get; set;
		}

		/// <summary>
		/// Indicates whether the User is an Administrator
		/// </summary>
		public bool IsSuperUser
		{
			get; set;
		}

		/// <summary>
		/// Gets or sets the Full Name of the User
		/// </summary>
		public string UserFullName
		{
			get; set;
		}

		/// <summary>
		/// Gets or sets the Email of the User
		/// </summary>
		public string UserEmail
		{
			get; set;
		}

		/// <summary>
		/// Gets or sets the Roles of the User
		/// The roles are stored in a pipe "|" separated string
		/// </summary>
		public string UserRoles
		{
			get; set;
		}


		

        public string Name { get; set; }

		

        #endregion
    }
}
