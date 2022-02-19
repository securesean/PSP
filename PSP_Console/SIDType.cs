namespace PSP_Console
{
    public enum SIDType
    {
        /*
         * SIDType - UInt8
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
               */
        SidEnumBase,
        SidTypeUser,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer,
    }

    class SIDEnum
    {

    }
}