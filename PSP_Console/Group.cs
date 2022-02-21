using System;

namespace PSP_Console
{
    class Group
    {
        public string Caption;
        public string Description;
        public string Domain;
        public DateTime InstallDate;
        public Boolean LocalAccount;
        public string Name;
        public string SID;
        public SIDType SIDType;
        public string Status;   

        /* It appears Name and Domain are the only required fields
         * 
        Caption - String
        Description - String
        *Domain - String
               The Domain property indicates the name of the Windows domain to which the group account belongs.
               Example: NA-SALES
        InstallDate - DateTime
        LocalAccount - Boolean
               The LocalAccount property indicates whether the account is defined on the local machine. To retrieve only accounts defined on the local machine state a query that includes the condition 'LocalAccount=TRUE'.
        *Name - String
            The Name property indicates the name of the Win32 group account on the domain specified by the Domain member of this class.
        SID - String
            The SID property contains the security identifier (SID) for this account. a SID is a string value of variable length used to identify a trustee. Each account has a unique SID issued by an authority (such as a Windows domain), stored in a security database. When a user logs on, the system retrieves the user's SID from the database and places it in the user's access token. The system uses the SID in the user's access token to identify the user in all subsequent interactions with Windows security. When a SID has been used as the unique identifier for a user or group, it cannot be used again to identify another user or group.
        SIDType - Enum
        Status - String
         **/

        public Group(string Domain, string Name)
        {
            this.Name = Name;
            this.Domain = Domain;
        }

        public Group(string Name, string Domain = "", string Caption = "", string Description = "", DateTime InstallDate = new DateTime(), Boolean LocalAccount = true, string SID = "", SIDType SIDType = SIDType.SidTypeUnknown, string Status = "UNKNOWN STATUS")
        {
            this.Name = Name;
            this.Domain = Domain;
            this.Caption = Caption;
            this.Description = Description;
            this.InstallDate = InstallDate;
            this.LocalAccount = LocalAccount;
            this.SID = SID;
            this.SIDType = SIDType;
            this.Status = Status;
        }



        public int CompareTo(Group other)
        {
            return Name.CompareTo(other.Name);
        }

        public Boolean Equals(Group other)
        {
            if (Caption.Equals(other.Caption)
                && Description.Equals(other.Description)
                && Domain.Equals(other.Domain)
                && InstallDate.Equals(other.InstallDate)
                && LocalAccount.Equals(other.LocalAccount)
                && Name.Equals(other.Name)
                && SID.Equals(other.SID)
                && SIDType.Equals(other.SIDType)
                && Status.Equals(other.Status)
                )
            {
                return true;
            }
            return false;
        }

        public Boolean FunctionallyEquals(Group other)
        {
            // && Description.Equals(other.Description)
            // && Domain.Equals(other.Domain)
            // && InstallDate.Equals(other.InstallDate)
            //if (Caption.Equals(other.Caption))
            if (LocalAccount.Equals(other.LocalAccount))
                if (Name.Equals(other.Name))
                    if (SID.Equals(other.SID))
                        if (SIDType.Equals(other.SIDType))
                            if (Status.Equals(other.Status))
                                return true;
            return false;
        }

        public bool isStandardGroup()
        {
            // List of 

            return false;
        }

        public bool isInterestingGroup()
        {
            // TODO: Fill this list out
            // List of 
            // if it's not OK, that's interesting
            if (!Status.Equals("OK"))
            {
                return true;
            }
            if (this.SIDType != SIDType.SidTypeAlias)
            {
                return true;
            }
            if (this.SID == "S-1-5-32-544")     // Administrators
            {
                return true;
            }
            return false;
        }
    }

    
}