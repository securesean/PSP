using System;

namespace PSP_Console
{
    class User
    {

        /*
       AccountType - UInt32
       The AccountType property contains flags describing the characteristics of Win32 user account:
       UF_TEMP_DUPLICATE_ACCOUNT - Local user account for users whose primary account is in another domain. This account provides user access to this domain, but not to any domain that trusts this domain.
       UF_NORMAL_ACCOUNT - default account type that representing a typical user. 
       UF_INTERDOMAIN_TRUST_ACCOUNT - account is for a system domain that trusts other domains.
       UF_WORKSTATION_TRUST_ACCOUNT - This is a computer account for a Windows NT/Windows 2000 machine that is a member of this domain.
       UF_SERVER_TRUST_ACCOUNT - account is for a system backup domain controller that is a member of this domain. 
       
       Possible Bit Values: 
       Bit 8 - Temporary duplicate account
       Bit 9 - Normal account
       Bit 11 - Interdomain trust account
       Bit 12 - Workstation trust account
       Bit 13 - Server trust account
       */
        public Int32 AccountType;

        /*  Caption - String */
        public string Caption;

        /* Description - String */
        public string Description;

        /* Disabled - Boolean
               The Disabled property determines whether the Win32 user account is disabled.
               Values: TRUE or FALSE. If TRUE, the user account is disabled. */
        public bool Disabled;

        /* Domain - String
               The Domain property indicates the name of the Windows domain to which the user account belongs. */
        public string Domain;

        /* FullName - String
               The FullName property indicates the full name of the local user. */
        public string FullName;

        /* InstallDate - DateTime*/
        /* LocalAccount - Boolean
               The LocalAccount property indicates whether the account is defined on the local machine. To retrieve only accounts defined on the local machine state a query that includes the condition 'LocalAccount=TRUE'.*/
        public DateTime InstallDate;

        /* Lockout - Boolean
               The Lockout property determines whether the user account is locked out of the Win32 system.
               Values: TRUE or FALSE. If TRUE, the user account is locked out.*/
        public bool Lockout;

        /* Name - String
               The Name property indicates the name of the Win32 user account on the domain specified by the Domain member of this class.*/
        public string Name;

        /* PasswordChangeable - Boolean
               The PasswordChangeable property determines whether the password on the Win32 user account can be changed.
               Values: TRUE or FALSE. If TRUE, the password can be changed.*/
        public bool PasswordChangeable;

        /* PasswordExpires - Boolean
               The PasswordExpires property determines whether the password on the Win32 user account will expire.
               Values: TRUE or FALSE. If TRUE, the password will expire.*/
        public bool PasswordExpires;

        /* PasswordRequired - Boolean
               The PasswordRequired property determines whether a password is required on the Win32 user account.
               Values: TRUE or FALSE. If TRUE, a password is required.*/
        public bool PasswordRequired;

        /* SID - String
               The SID property contains the security identifier (SID) for this account. a SID is a string value of variable length used to identify a trustee. Each account has a unique SID issued by an authority (such as a Windows domain), stored in a security database. When a user logs on, the system retrieves the user's SID from the database and places it in the user's access token. The system uses the SID in the user's access token to identify the user in all subsequent interactions with Windows security. When a SID has been used as the unique identifier for a user or group, it cannot be used again to identify another user or group.*/
        public string SID;

        /* SIDType - UInt8
        
               Qualifiers: CIMTYPE, Description, Fixed, MappingStrings, read, ValueMap, Values
       
               The SIDType property contains enumerated values that specify the type of security identifier (SID). SIDTypes include:
               SidTypeUser - Indicates a user SID.
               SidTypeGroup - Indicates a group SID.
               SidTypeDomain - Indicates a domain SID.
               SidTypeAlias - Indicates an alias SID.
               SidTypeWellKnownGroup - Indicates a SID for a well-known group.
               SidTypeDeletedAccount - Indicates a SID for a deleted account.
               SidTypeInvalid - Indicates an invalid SID.
               SidTypeUnknown - Indicates an unknown SID type.
               SidTypeComputer - Indicates a SID for a computer.
       
       
               Possible Enumeration Values: 
               1 - SidTypeUser
               2 - SidTypeGroup
               3 - SidTypeDomain
               4 - SidTypeAlias
               5 - SidTypeWellKnownGroup
               6 - SidTypeDeletedAccount
               7 - SidTypeInvalid
               8 - SidTypeUnknown
               9 - SidTypeComputer
        Status - String
       
        */
        public SIDType SIDType;

        public User(string Name,
            string Domain,
            Int32 AccountType = 0,
            string Caption = "",
            string Description = "",
            bool Disabled = false,
            string FullName = "",
            DateTime InstallDate = new DateTime(),
            bool Lockout = false,
            bool PasswordChangeable = true,
            bool PasswordExpires = true,
            bool PasswordRequired = true,
            string SID = "",
            SIDType SIDType = SIDType.SidTypeUser)
        {
            this.AccountType = AccountType;
            this.Caption = Caption;
            this.Description = Description;
            this.Disabled = Disabled;
            this.Domain = Domain;
            this.FullName = FullName;
            this.InstallDate = InstallDate;
            this.Lockout = Lockout;
            this.Name = Name;
            this.PasswordChangeable = PasswordChangeable;
            this.PasswordExpires = PasswordExpires;
            this.PasswordRequired = PasswordRequired;
            this.SID = SID;
            this.SIDType = SIDType;
        }


        public int CompareTo(User other)
        {
            return Name.CompareTo(other.Name);
        }

        public Boolean Equals(User other)
        {
            if (
                this.AccountType.Equals(other.AccountType) &&
                this.Caption.Equals(other.Caption) &&
                this.Description.Equals(other.Description) &&
                this.Disabled.Equals(other.Disabled) &&
                this.Domain.Equals(other.Domain) &&
                this.FullName.Equals(other.FullName) &&
                this.InstallDate.Equals(other.InstallDate) &&
                this.Lockout.Equals(other.Lockout) &&
                this.Name.Equals(other.Name) &&
                this.PasswordChangeable.Equals(other.PasswordChangeable) &&
                this.PasswordExpires.Equals(other.PasswordExpires) &&
                this.PasswordRequired.Equals(other.PasswordRequired) &&
                this.SID.Equals(other.SID) &&
                this.SIDType.Equals(other.SIDType)
                )
            {
                return true;
            }
            return false;
        }

        public Boolean FunctionallyEquals(User other)
        {
            if (
                this.AccountType.Equals(other.AccountType) &&
                // this.Caption.Equals(other.Caption) &&
                // this.Description.Equals(other.Description) &&
                this.Disabled.Equals(other.Disabled) &&
                // this.Domain.Equals(other.Domain) &&
                // this.FullName.Equals(other.FullName) &&
                // this.InstallDate.Equals(other.InstallDate) &&
                this.Lockout.Equals(other.Lockout) &&
                this.Name.Equals(other.Name) &&
                // this.PasswordChangeable.Equals(other.PasswordChangeable) &&
                // this.PasswordExpires.Equals(other.PasswordExpires) &&
                this.PasswordRequired.Equals(other.PasswordRequired) &&
                this.SID.Equals(other.SID) &&
                this.SIDType.Equals(other.SIDType)
                )
            {
                return true;
            }
            return false;
        }
    }
}