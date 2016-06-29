configuration CreateAppServer
{
    param
    (
        [Parameter(Mandatory)]
        [String]$DnsServerAddress,
        [Parameter(Mandatory)]
        [String]$MachineName,
        [Parameter(Mandatory)]
        [String]$DomainName,
        [Parameter(Mandatory)]
        [PSCredential]$AdminCreds
    )
    Import-DscResource -Module xNetworking, xComputerManagement, xRemoteDesktopSessionHost
    [PSCredential]$DomainCreds = New-Object System.Management.Automation.PSCredential("${DomainName}\$($AdminCreds.UserName)", $AdminCreds.Password)
    [String]$localhost = $MachineName + "." + $DomainName
    [String]$collectionName = 'mycollection'
    [String]$collectionDescription = 'My first collection'
    [String]$commandLineParameter = '/v:' + $DnsServerAddress

    Node localhost
    {
        LocalConfigurationManager
        {
            ConfigurationMode = 'ApplyOnly'
            RebootNodeIfNeeded = $true
        }

        xDnsServerAddress DnsServerAddress
        {
            Address = $DnsServerAddress
            InterfaceAlias = 'Ethernet'
            AddressFamily  = 'IPv4'
        }

        xComputer JoinDomain
        {
            Name = $MachineName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn = "[xDnsServerAddress]DnsServerAddress"
        }

        WindowsFeature Remote-Desktop-Services
        {
            Ensure = "Present"
            Name = "Remote-Desktop-Services"
            DependsOn = "[xComputer]JoinDomain"
        }

        WindowsFeature RDS-RD-Server
        {
            Ensure = "Present"
            Name = "RDS-RD-Server"
            DependsOn = "[xComputer]JoinDomain"
        }

        WindowsFeature RDS-Connection-Broker
        {
            Ensure = "Present"
            Name = "RDS-Connection-Broker"
            DependsOn = "[xComputer]JoinDomain"
        }

        WindowsFeature RDS-Licensing
        {
            Ensure = "Present"
            Name = "RDS-Licensing"
            DependsOn = "[xComputer]JoinDomain"
        }

        WindowsFeature RDS-Web-Access
        {
            Ensure = "Present"
            Name = "RDS-Web-Access"
            DependsOn = "[xComputer]JoinDomain"
        }

        xRDSessionDeployment Deployment
        {
            SessionHost = $localhost
            ConnectionBroker = $localhost
            WebAccessServer = $localhost
            DependsOn = "[WindowsFeature]Remote-Desktop-Services", "[WindowsFeature]RDS-RD-Server"
        }

        xRDSessionCollection Collection
        {
            CollectionName = $collectionName
            CollectionDescription = $collectionDescription
            SessionHost = $localhost
            ConnectionBroker = $localhost
            DependsOn = "[xRDSessionDeployment]Deployment"
        }

        xRDSessionCollectionConfiguration CollectionConfiguration
        {
            CollectionName = $collectionName
            CollectionDescription = $collectionDescription
            ConnectionBroker = $localhost
            TemporaryFoldersDeletedOnExit = $false
            AuthenticateUsingNLA = $false
            DisconnectedSessionLimitMin = 1
            DependsOn = "[xRDSessionCollection]Collection"
        }

        xRDRemoteApp Notepad
        {
            CollectionName = $collectionName
            DisplayName = "Notepad"
            FilePath = "C:\Windows\System32\notepad.exe"
            Alias = "notepad"
            CommandLineSetting = "Allow"
            DependsOn = "[xRDSessionCollection]Collection"
        }

        xRDRemoteApp Mstsc
        {
            CollectionName = $collectionName
            DisplayName = "Remote Desktop Connection"
            FilePath = "C:\Windows\System32\mstsc.exe"
            Alias = "mstsc"
            CommandLineSetting = "Require"
            RequiredCommandLine = $commandLineParameter
            DependsOn = "[xRDSessionCollection]Collection"
        }
    }
}
