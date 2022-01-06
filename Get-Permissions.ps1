function Get-Permissions {

    <#
    .SYNOPSIS
    Get-Permissions is used to grab the file/folder properties from shared directories/files, or specific directories
    .DESCRIPTION
    Get-Permissions can be used to not only get the permissions of files/folders it also gets the size of files, sha256 hash, absolute path, when a file was last modified and when it was created.
    It stores all the properties in hash tables and exports it to a CSV in the current working directory so you can import to data to a tool you like such as powerBI
    .PARAMETER Path
    Used to specify path you want to scan
    .PARAMETER Outfile
    Used to specify a location to export the CSV to
    .PARAMETER Shares
    Switch parameter used to specify if you want to scan only shared folders and their files
    .PARAMETER folderShares
    Switch parameter used to specify if you want to scan only directories inside of shared folders
    .PARAMETER Directory
    Switch parameter used to specify if you want to scan only Directories, must be used with the $Path parameter
    .EXAMPLE
    Get-Permissions -Path C:\ -Directory
    .EXAMPLE
    Get-Permissions -Shares
    .EXAMPLE
    Get-Permissions -folderShares
    .NOTES
    Author: Adrian M.
    Last Edit: 01-06-2022
    Version 1.0 - Initial Release
    
    #>
    [cmdletbinding()]
    param (
        [parameter(Mandatory = $false, Position = 0)]
        [string[]]$Path,

        [parameter(Mandatory = $false, Position = 1)]
        [string]$Outfile = '.\Permissions.csv',

        [parameter(Mandatory = $false, Position = 2)]
        [switch]$Shares,

        [parameter(Mandatory = $false, Position = 3)]
        [switch]$folderShares,

        [Parameter(Mandatory = $false, Position = 4)]
        [switch]$Directory
    )
    

    BEGIN {

        #Get current date to calculate file age
        $Date = Get-Date

        if ($PSBoundparameters.ContainsKey('Path')) {
            Write-Verbose "Beginning scan of: $Path"
        }

        #Create exclusions so scanner doesn't scan files where it may not have permissions
        $Exclusions = {`
            ($_.FullName -notlike "*\Windows\*") -and ($_.FullName -notlike "*\Windows.old\*") -and ($_.FullName -notlike "*\Program Files\*") `
            -and ($_.FullName -notlike "*\Program Files (x86)\*") -and ($_.FullName -notlike "*\Program Data\*")`
            -and ($_.FullName -notlike "*\Appdata\*")`
        }#/Exclusions

        #Arguments for get-childitem for directory only scan
        $argumentsFolder = @{
            'Path'        = $Path
            'Directory'   = $true
            'Recurse'     = $true
            'ErrorAction' = 'Ignore'
            'Force' = $true
        }#/Folder arguments

        #Arguments for get-childitem for all items
        $argumentsFile = @{
            'Path'        = $Path
            'Recurse'     = $true
            'ErrorAction' = 'Ignore'
            'Force' = $true
        }#/File arguments
        


        # If Directory parameter is specified run this to create a $Folders variable to use later
        if ($PSBoundParameters.ContainsKey('Directory')) {
            Write-Verbose "Scanning only for folder permissions"

            $Folders = Get-ChildItem @argumentsFolder | Where-Object $Exclusions
        } #/if


        # If Shares parameter is specified run this to grab a list of shared folders on the server to scan through later
        elseif (($PSBoundParameters.ContainsKey('Shares')) -or ($PSBoundparameters.ContainsKey('folderShares'))) {
            Write-Verbose "Grabbing list of Shared Folders..."

            $sharedFolders = Get-SmbShare | Where-Object {($_.Name -ne 'C$') -and ($_.Name -ne 'Admin$') -and ($_.Name -ne 'IPC$')} | Select-Object -ExpandProperty Path
            
        } #/elif


        # If no paramater is specified scan all files
        else {
            Write-Verbose "Scanning for all file and folder permissions"

            $Files = Get-ChildItem @argumentsFile  | Where-Object $Exclusions
        } #/Else
    }
        
        

    Process {

        if ($PSBoundParameters.ContainsKey('Directory')) {


            foreach ($folder in $Folders) {

                Write-Verbose "Getting permissions for $folder..."

                $Object_Property = @{
                    'Folder Name'   = ''
                    'Path'          = ''
                    'Owner'         = ''
                    'Access'        = ''
                    'Age'           = ''
                    'Last Modified' = ''
                }

                $Permissions = Get-Acl -Path $folder.fullname

                $Age = $Date - $folder.CreationTime

                $LastModified = $Date - $folder.LastWriteTime

                $Object_Property.'Folder Name' = $folder.Name
                $Object_Property.Path = $Folder.FullName
                $Object_Property.Owner = $Permissions.Owner
                $Object_Property.Access = $Permissions.AccessToString 
                $Object_Property.Age = "$($Age.Days) Days"
                $Object_Property.'Last Modified' = "$($LastModified.Days) Day(s)"

                $Obj = New-Object -TypeName PSObject -Property $Object_Property

                $Obj | Export-Csv -Path $Outfile -Append -NoTypeInformation

                Write-Verbose "Adding object properties to $OutFile"
                
            }#/foreach            
        }#/If

        elseif (($PSBoundparameters.ContainsKey('Shares')) -or ($PSBoundparameters.ContainsKey('folderShares'))) {
            
            foreach ($sharedFolder in $sharedFolders) {

                if ($PSBoundparameters.ContainsKey('folderShares')) {
                    $sharePath = Get-ChildItem -Path $sharedFolder -Recurse -ErrorAction Ignore -Directory

                }

                else {
                    $sharePath = Get-ChildItem -Path $sharedFolder -Recurse -ErrorAction Ignore
                }

                foreach ($folder in $sharePath) {


                    ######Need to figure out how to fix getting the size of the folders
                    #$folderSize += [int]$folderSize1

                    #$folderSize1 = 0
                    
                    if ($PSBoundparameters.ContainsKey('folderShares')) {

                        Write-Verbose "Getting permissions for $folder..."

                        $Object_Property = @{
                            'Folder Name'   = ''
                            'Path'          = ''
                            'Owner'         = ''
                            'Access'        = ''
                            'Age'           = ''
                            'Last Modified' = ''
                        }
        
                        $Permissions = Get-Acl -Path $folder.fullname
        
                        $Age = $Date - $folder.CreationTime
        
                        $LastModified = $Date - $folder.LastWriteTime
        
                        $Object_Property.'Folder Name' = $folder.Name
                        $Object_Property.Path = $Folder.FullName
                        $Object_Property.Owner = $Permissions.Owner
                        $Object_Property.Access = $Permissions.AccessToString 
                        $Object_Property.Age = "$($Age.Days) Days"
                        $Object_Property.'Last Modified' = "$($LastModified.Days) Day(s)"
        
                        $Obj = New-Object -TypeName PSObject -Property $Object_Property
        
                        $Obj | Export-Csv -Path $Outfile -Append -NoTypeInformation
        
                        Write-Verbose "Adding object properties to $OutFile"
                    }#/If

                    else {

                        foreach ($file in $folder) {

                            Write-Verbose "Getting permissions for $file..."

                            $Object_Property = @{
                                'File Name'     = ''
                                'Path'          = ''
                                'Owner'         = ''
                                'Access'        = ''
                                'Age'           = ''
                                'Last Modified' = ''
                                'Size(MB)'      = ''
                                'sha256'        = ''
                                #'Folder Size(MB)' = 0
                            }

                            $Permissions = Get-Acl -Path $file.fullname

                            $Age = $Date - $file.CreationTime

                            $LastModified = $Date - $file.LastWriteTime

                            $sha256Hash = Get-FileHash -Path $file.FullName -Algorithm sha256

                            $size =  "{0:N0}" -f ($file.Length / 1MB)

                            $Object_Property.'File Name' = $file.name
                            $Object_Property.Path = $file.FullName
                            $Object_Property.Owner = $Permissions.Owner
                            $Object_Property.Access = $Permissions.AccessToString 
                            $Object_Property.Age = "$($Age.Days) Days"
                            $Object_Property.'Last Modified' = "$($LastModified.Days) Day(s)"
                            $Object_Property.'sha256' = $sha256Hash.Hash
                            $Object_Property.'Size(MB)' = "$($size) MB"
                            #$folderSize1 += [int]$size


                            $Obj = New-Object -TypeName PSObject -Property $Object_Property

                            $Obj | Export-Csv -Path $Outfile -Append -NoTypeInformation

                            Write-Verbose "Adding object properties to $OutFile"
                        }#/foreach
                    }#/else
                }#/foreach

            }#/foreach
        }#/elif
        
        else {

            foreach ($file in $Files) {

                Write-Verbose "Getting permissions for $file..."

                $Object_Property = @{
                    'File Name'     = ''
                    'Path'          = ''
                    'Owner'         = ''
                    'Access'        = ''
                    'Age'           = ''
                    'Last Modified' = ''
                    'Size(MB)'      = ''
                    'sha256'        = ''
                }

                $Permissions = Get-Acl -Path $file.fullname

                $Age = $Date - $file.CreationTime

                $LastModified = $Date - $file.LastWriteTime

                $sha256Hash = Get-FileHash -Path $file.FullName -Algorithm sha256

                $size =  "{0:N0}" -f ($file.Length / 1MB)

                $Object_Property.'File Name' = $file.name
                $Object_Property.Path = $file.FullName
                $Object_Property.Owner = $Permissions.Owner
                $Object_Property.Access = $Permissions.AccessToString 
                $Object_Property.Age = "$($Age.Days) Day(s)"
                $Object_Property.'Last Modified' = "$($LastModified.Days) Day(s)"
                $Object_Property.'Size(MB)' = "$($size) MB"
                $Object_Property.'sha256' = $sha256Hash.Hash

                $Obj = New-Object -TypeName PSObject -Property $Object_Property

                $Obj | Export-Csv -Path $Outfile -Append -NoTypeInformation

                Write-Verbose "Adding object properties to $OutFile"
                
            }
            
        }
    }
    END {}
}

Get-Permissions -Shares -Verbose