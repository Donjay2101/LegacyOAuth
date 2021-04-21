using System;
using System.Collections;
using System.Security.Principal;

namespace SSOSecurity
{
    /// <summary>
    /// Represents a SSO Principal
    /// </summary>
    [Serializable]
	public class SSOPrincipal : IPrincipal
	{
		# region private variables
		
		private IIdentity identity;
		private ArrayList roles;

		#endregion

		# region Constructor
		/// <summary>
		/// Initializes a new instance of the GenericPrincipal class 
		/// from a SSOIdentity and an ArrayList of role names 
		/// to which the user represented by that SSOIdentity belongs
		/// </summary>
		/// <param name="id"></param>
		/// <param name="rolesArray"></param>
		public SSOPrincipal(IIdentity id, ArrayList rolesArray)
		{
			identity = id;
			roles = rolesArray;
		}
		#endregion

		# region Methods
		/// <summary>
		/// Determines whether the current SSOPrincipal belongs to the specified role.
		/// </summary>
		/// <param name="role">The name of the role for which to check membership</param>
		/// <returns>true if the current SSOPrincipal is a member of the specified role; 
		/// otherwise, false.</returns>
		public bool IsInRole(string role)
		{
			return roles.Contains( role );
		}

		#endregion

		# region Properties
		/// <summary>
		/// Gets the SSOIdentity of the user represented by the current SSOPrincipal.
		/// </summary>
		public IIdentity Identity
		{
			get { return identity; }
			set { identity = value; }
		}
		#endregion
	}
}